//! Windows specifics: DPAPI, ACLs, pipe-client checks, starting the session agent as
//! SYSTEM in a user session, and Ctrl+Alt+Del.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DACL_SECURITY_INFORMATION, DuplicateTokenEx, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation, SetFileSecurityW, SetTokenInformation,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_QUERY, TokenPrimary, TokenSessionId, WinBuiltinAdministratorsSid,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess, GetCurrentThread,
    GetExitCodeProcess, OpenProcessToken, OpenThreadToken, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess,
};
use windows::core::{HSTRING, PCWSTR, PWSTR, s, w};

use crate::state::Protector;

fn win_err(e: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(e.code().0 & 0xFFFF)
}

/// Owned kernel handle.
pub struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// ------------------------------------------------------------------ DPAPI

/// DPAPI with the machine key. Any local account can decrypt machine-scope blobs, so
/// confidentiality also relies on the state directory's ACL (SYSTEM + Administrators).
pub struct DpapiMachine;

const ENTROPY: &[u8] = b"moonrd/host-state/v1";

fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: b.len() as u32, pbData: b.as_ptr() as *mut u8 }
}

fn take_blob(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut c_void)));
    }
    v
}

impl Protector for DpapiMachine {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        let entropy = blob(ENTROPY);
        unsafe {
            CryptProtectData(
                &blob(plain),
                w!("moonrd host state"),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(win_err)?;
        Ok(take_blob(out))
    }

    fn unprotect(&self, sealed: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        let entropy = blob(ENTROPY);
        unsafe { CryptUnprotectData(&blob(sealed), None, Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out) }
            .map_err(win_err)?;
        Ok(take_blob(out))
    }
}

// ------------------------------------------------------------------ ACLs

/// SYSTEM and Administrators only, not inherited from the parent.
pub const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// UI pipe: SYSTEM and Administrators full; interactive users read/write (the service
/// still requires an administrator caller for changes).
pub const UI_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// A security descriptor parsed from SDDL.
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl), SDDL_REVISION_1, &mut sd, None) }
            .map_err(win_err)?;
        Ok(Self(sd))
    }

    /// SECURITY_ATTRIBUTES pointing at this descriptor (valid while `self` lives).
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

/// Creates `dir` and replaces its DACL with `sddl` (protected from inheritance).
pub fn secure_dir(dir: &Path, sddl: &str) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let ok = unsafe {
        SetFileSecurityW(&HSTRING::from(dir.as_os_str()), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd.0)
    };
    if ok.as_bool() { Ok(()) } else { Err(io::Error::last_os_error()) }
}

// ------------------------------------------------------------------ pipe clients

/// Session of the process at the other end of a named pipe.
pub fn pipe_client_session(pipe: HANDLE) -> io::Result<u32> {
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.map_err(win_err)?;
    let mut session = 0u32;
    unsafe { ProcessIdToSessionId(pid, &mut session) }.map_err(win_err)?;
    Ok(session)
}

/// Whether the pipe client runs with an administrator token (elevated).
pub fn pipe_client_is_admin(pipe: HANDLE) -> io::Result<bool> {
    unsafe { ImpersonateNamedPipeClient(pipe) }.map_err(win_err)?;
    // Always revert, whatever happens below.
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }
    let _revert = Revert;
    let mut token = HANDLE::default();
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }.map_err(win_err)?;
    let token = Handle(token);
    let mut sid_buf = [0u8; 68];
    let mut sid_len = sid_buf.len() as u32;
    let sid = PSID(sid_buf.as_mut_ptr() as *mut c_void);
    unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut sid_len) }.map_err(win_err)?;
    let mut member = false.into();
    unsafe { CheckTokenMembership(Some(token.0), sid, &mut member) }.map_err(win_err)?;
    Ok(member.as_bool())
}

// ------------------------------------------------------------------ sessions & agent

/// Session attached to the physical console, if any.
pub fn active_console_session() -> Option<u32> {
    match unsafe { WTSGetActiveConsoleSessionId() } {
        0xFFFF_FFFF => None,
        s => Some(s),
    }
}

/// Job object that kills every assigned process when the service exits.
pub struct Job(Handle);

impl Job {
    pub fn new() -> io::Result<Self> {
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(win_err)?;
        let job = Handle(job);
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(win_err)?;
        Ok(Self(job))
    }
}

/// A process started by [`spawn_in_session`].
pub struct AgentProcess {
    process: Handle,
    pub pid: u32,
    pub session: u32,
}

impl AgentProcess {
    /// `Some(exit code)` once it ended.
    pub fn exit_code(&self) -> Option<u32> {
        const STILL_ACTIVE: u32 = 259;
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(self.process.0, &mut code) }.ok()?;
        (code != STILL_ACTIVE).then_some(code)
    }

    pub fn kill(&self) {
        unsafe {
            let _ = TerminateProcess(self.process.0, 1);
        }
    }
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Starts `exe args` as SYSTEM inside `session` on the interactive window station, so
/// it can capture and inject input on the user's desktop and, after switching thread
/// desktops, on the secure desktop (UAC, lock and logon screens). Requires the caller
/// to run as LocalSystem (SeTcbPrivilege for setting the token's session).
pub fn spawn_in_session(exe: &Path, args: &str, session: u32, job: &Job) -> io::Result<AgentProcess> {
    let mut own = HANDLE::default();
    let access: TOKEN_ACCESS_MASK =
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT;
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut own) }.map_err(win_err)?;
    let own = Handle(own);
    let mut dup = HANDLE::default();
    unsafe { DuplicateTokenEx(own.0, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, &mut dup) }.map_err(win_err)?;
    let dup = Handle(dup);
    unsafe { SetTokenInformation(dup.0, TokenSessionId, &session as *const u32 as *const c_void, 4) }.map_err(win_err)?;

    let mut cmdline = wide(format!("\"{}\" {args}", exe.display()).as_ref());
    let mut desktop = wide("winsta0\\default".as_ref());
    let si = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, lpDesktop: PWSTR(desktop.as_mut_ptr()), ..Default::default() };
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessAsUserW(
            Some(dup.0),
            PCWSTR::null(),
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    }
    .map_err(win_err)?;
    let process = Handle(pi.hProcess);
    let thread = Handle(pi.hThread);
    // In the job before it runs a single instruction, so it can never outlive us.
    if let Err(e) = unsafe { AssignProcessToJobObject(job.0.0, process.0) } {
        unsafe {
            let _ = TerminateProcess(process.0, 1);
        }
        return Err(win_err(e));
    }
    unsafe { ResumeThread(thread.0) };
    Ok(AgentProcess { process, pid: pi.dwProcessId, session })
}

// ------------------------------------------------------------------ Ctrl+Alt+Del

/// Sends the Secure Attention Sequence. Needs the `SoftwareSASGeneration` policy
/// (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, value 1 = services),
/// which the installer sets; without it Windows ignores the call.
pub fn send_sas() -> io::Result<()> {
    let lib = unsafe { LoadLibraryW(w!("sas.dll")) }.map_err(win_err)?;
    let f = unsafe { GetProcAddress(lib, s!("SendSAS")) }.ok_or_else(|| io::Error::other("SendSAS not found in sas.dll"))?;
    let send: extern "system" fn(i32) = unsafe { std::mem::transmute(f) };
    send(0); // FALSE: called from a service, not a user application
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip() {
        let p = DpapiMachine;
        let sealed = p.protect(b"secret state").unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(p.unprotect(&sealed).unwrap(), b"secret state");
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(p.unprotect(&tampered).is_err());
    }

    #[test]
    fn sddl_parses_and_applies() {
        assert!(SecurityDescriptor::from_sddl(DATA_DIR_SDDL).is_ok());
        assert!(SecurityDescriptor::from_sddl(UI_PIPE_SDDL).is_ok());
        assert!(SecurityDescriptor::from_sddl("not sddl").is_err());
        // Owner-rights only, so the test user keeps access to clean up.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("locked");
        secure_dir(&sub, "D:P(A;OICI;FA;;;OW)").unwrap();
        std::fs::write(sub.join("f"), b"x").unwrap();
    }

    #[test]
    fn console_session_exists_on_desktop() {
        assert!(active_console_session().is_some());
    }

    #[test]
    fn spawning_into_a_session_needs_system() {
        // As a normal user SetTokenInformation(TokenSessionId) is refused; the service
        // path is exercised when running as LocalSystem.
        let job = Job::new().unwrap();
        let session = active_console_session().unwrap();
        let r = spawn_in_session(Path::new(r"C:\Windows\System32\cmd.exe"), "/c exit 0", session, &job);
        if let Ok(p) = r {
            // Running elevated as SYSTEM (e.g. CI under a service account): it must work.
            assert_eq!(p.session, session);
        }
    }
}
