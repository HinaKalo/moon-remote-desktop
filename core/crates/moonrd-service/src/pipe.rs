//! JSON API for the desktop UI over a local named pipe.
//!
//! One request per line, one response per line:
//!
//! ```text
//! → {"id":1,"method":"status"}
//! ← {"id":1,"ok":true,"result":{...}}
//! ← {"id":2,"ok":false,"error":{"code":"forbidden","message":"..."}}
//! ```
//!
//! `status` is open to any interactive user on this machine. Every change (registering
//! the host, setting the PIN, LAN mode, unregistering) requires an administrator caller,
//! as Chrome Remote Desktop requires elevation to enable remote access: otherwise any
//! other local account could take over the host. The device key never leaves the
//! service; registration works by the service signing the server's challenge.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::state::{Host, Registration, SetPinError};

/// Production pipe name.
pub const PIPE_NAME: &str = r"\\.\pipe\moonrd-service";
/// Pipe name in console (development) mode.
pub const DEV_PIPE_NAME: &str = r"\\.\pipe\moonrd-service-dev";
/// Longest accepted request line.
pub const MAX_REQUEST: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

fn ok(id: u64, result: Value) -> Response {
    Response { id, ok: true, result: Some(result), error: None }
}

fn err(id: u64, code: &str, message: impl Into<String>) -> Response {
    Response { id, ok: false, result: None, error: Some(ApiError { code: code.into(), message: message.into() }) }
}

/// Who is calling, established from the pipe handle (not from the request).
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    pub admin: bool,
    pub session: u32,
}

/// Live facts the pipe adds to `status` (agent state etc.).
pub type StatusExtra = Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignParams {
    nonce: String,
    user_sub: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteParams {
    server_url: String,
    device_id: String,
    user_sub: String,
    name: String,
    device_token: String,
    roster_key: String,
    roster_key_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinParams {
    pin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LanParams {
    enabled: bool,
}

fn params<T: for<'de> Deserialize<'de>>(v: &Value) -> Result<T, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

const MUTATING: &[&str] = &["sign_registration", "complete_registration", "unregister", "set_pin", "set_lan_direct"];

/// Handles one request. Synchronous (Argon2 in `set_pin` takes tens of milliseconds);
/// the server runs it on a blocking thread.
pub fn handle(host: &Mutex<Host>, caller: Caller, req: Request, extra: &StatusExtra) -> Response {
    let id = req.id;
    if MUTATING.contains(&req.method.as_str()) && !caller.admin {
        return err(id, "forbidden", "this change needs administrator rights");
    }
    let mut host = match host.lock() {
        Ok(h) => h,
        Err(p) => p.into_inner(),
    };
    match req.method.as_str() {
        "status" => {
            let r = host.state.registration.as_ref();
            let public = host.state.device_seed.map(|s| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&s).verifying_key().to_bytes())
            });
            ok(
                id,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "registered": r.is_some(),
                    "deviceId": r.map(|r| r.device_id.clone()),
                    "name": r.map(|r| r.name.clone()),
                    "userSub": r.map(|r| r.user_sub.clone()),
                    "serverUrl": r.map(|r| r.server_url.clone()),
                    "publicKey": public,
                    "pinSet": host.state.pin.is_some(),
                    "lanDirect": host.state.lan_direct,
                    "pairings": host.state.pairings.list().iter().map(|p| json!({"label": p.label, "deviceId": p.viewer_device_id, "created": p.created})).collect::<Vec<_>>(),
                    "lockedForSecs": host.state.lockout.retry_after(moonrd_session::handshake::HostStore::now(&*host)),
                    "callerIsAdmin": caller.admin,
                    "live": extra,
                }),
            )
        }
        "sign_registration" => match params::<SignParams>(&req.params) {
            Ok(p) if p.kind == "host" || p.kind == "viewer" => match host.sign_registration(&p.nonce, &p.user_sub, &p.kind) {
                Ok((public_key, signature)) => ok(id, json!({"publicKey": public_key, "signature": signature})),
                Err(e) => err(id, "internal", e.to_string()),
            },
            Ok(_) => err(id, "bad_request", "kind must be host or viewer"),
            Err(e) => err(id, "bad_request", e),
        },
        "complete_registration" => match params::<CompleteParams>(&req.params) {
            Ok(p) => {
                if !p.device_token.starts_with("mrdd_") || p.device_id.is_empty() || p.user_sub.is_empty() {
                    return err(id, "bad_request", "incomplete registration");
                }
                let reg = Registration {
                    server_url: p.server_url,
                    device_id: p.device_id,
                    user_sub: p.user_sub,
                    name: p.name,
                    device_token: p.device_token,
                    roster_key: p.roster_key,
                    roster_key_id: p.roster_key_id,
                };
                match host.complete_registration(reg) {
                    Ok(()) => ok(id, json!({})),
                    Err(e) => err(id, "internal", e.to_string()),
                }
            }
            Err(e) => err(id, "bad_request", e),
        },
        "unregister" => match host.unregister() {
            Ok(()) => ok(id, json!({})),
            Err(e) => err(id, "internal", e.to_string()),
        },
        "set_pin" => match params::<PinParams>(&req.params) {
            Ok(p) => match host.set_pin(&p.pin) {
                Ok(()) => ok(id, json!({})),
                Err(SetPinError::Pin(e)) => err(id, "bad_pin", e.to_string()),
                Err(SetPinError::Io(e)) => err(id, "internal", e.to_string()),
            },
            Err(e) => err(id, "bad_request", e),
        },
        "set_lan_direct" => match params::<LanParams>(&req.params) {
            Ok(p) => {
                host.state.lan_direct = p.enabled;
                match host.save() {
                    Ok(()) => ok(id, json!({})),
                    Err(e) => err(id, "internal", e.to_string()),
                }
            }
            Err(e) => err(id, "bad_request", e),
        },
        other => err(id, "unknown_method", format!("unknown method {other}")),
    }
}

/// Parses and handles one request line; malformed input gets an error with id 0.
pub fn handle_line(host: &Mutex<Host>, caller: Caller, line: &[u8], extra: &StatusExtra) -> Response {
    match serde_json::from_slice::<Request>(line) {
        Ok(req) => handle(host, caller, req, extra),
        Err(e) => err(0, "bad_request", e.to_string()),
    }
}

/// The pipe server (Windows).
#[cfg(windows)]
pub mod server {
    use std::os::windows::io::AsRawHandle;
    use std::sync::Arc;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows::Win32::Foundation::HANDLE;

    use super::*;
    use crate::win::{SecurityDescriptor, pipe_client_is_admin, pipe_client_session};

    pub struct Options {
        pub name: String,
        pub sddl: String,
        /// Console mode: treat every caller as an administrator (the pipe's ACL then
        /// admits only the current user).
        pub trust_all: bool,
    }

    fn create(opts: &Options, sd: &SecurityDescriptor, first: bool) -> std::io::Result<NamedPipeServer> {
        let mut sa = sd.attributes();
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first).reject_remote_clients(true).max_instances(16);
        // SAFETY: `sa` points at `sd`, which outlives the call.
        unsafe { o.create_with_security_attributes_raw(&opts.name, &mut sa as *mut _ as *mut std::ffi::c_void) }
    }

    /// Serves until `shutdown` resolves. `extra` supplies live status; `on_state_change`
    /// is invoked after a successful mutating request (e.g. registration or unregister)
    /// so the network stack can reload immediately.
    pub async fn serve(
        opts: Options,
        host: Arc<Mutex<Host>>,
        extra: Arc<dyn Fn() -> StatusExtra + Send + Sync>,
        on_state_change: Arc<dyn Fn() + Send + Sync>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let sd = SecurityDescriptor::from_sddl(&opts.sddl)?;
        // first_pipe_instance: fail if someone else already squats on the name.
        let mut server = create(&opts, &sd, true)?;
        loop {
            tokio::select! {
                r = server.connect() => r?,
                _ = shutdown.changed() => return Ok(()),
            }
            let conn = server;
            server = create(&opts, &sd, false)?;
            let trust_all = opts.trust_all;
            let (host, extra, on_change) = (host.clone(), extra.clone(), on_state_change.clone());
            tokio::spawn(async move {
                let _ = serve_conn(conn, trust_all, host, extra, on_change).await;
            });
        }
    }

    async fn serve_conn(
        conn: NamedPipeServer,
        trust_all: bool,
        host: Arc<Mutex<Host>>,
        extra: Arc<dyn Fn() -> StatusExtra + Send + Sync>,
        on_state_change: Arc<dyn Fn() + Send + Sync>,
    ) -> std::io::Result<()> {
        let raw_handle = conn.as_raw_handle() as usize;
        let (r, mut w) = tokio::io::split(conn);
        let mut reader = BufReader::new(r);
        let mut line = Vec::new();
        let mut cached_caller: Option<Caller> = None;
        loop {
            line.clear();
            let n = (&mut reader).take(MAX_REQUEST as u64 + 1).read_until(b'\n', &mut line).await?;
            if n == 0 {
                return Ok(());
            }
            if line.len() > MAX_REQUEST {
                let resp = super::err(0, "bad_request", "request too large");
                w.write_all(&[serde_json::to_vec(&resp)?, b"\n".to_vec()].concat()).await?;
                return Ok(());
            }
            // Windows requires reading from a named pipe before ImpersonateNamedPipeClient
            // succeeds (otherwise it fails with ERROR_CANNOT_IMPERSONATE).
            let caller = *cached_caller.get_or_insert_with(|| {
                let handle = HANDLE(raw_handle as *mut std::ffi::c_void);
                Caller {
                    admin: trust_all || pipe_client_is_admin(handle).unwrap_or(false),
                    session: pipe_client_session(handle).unwrap_or(u32::MAX),
                }
            });
            let (host2, req_line, status) = (host.clone(), line.clone(), extra());
            let (resp, mutated) = tokio::task::spawn_blocking(move || {
                let is_mut = serde_json::from_slice::<Request>(&req_line)
                    .ok()
                    .is_some_and(|r| MUTATING.contains(&r.method.as_str()));
                let resp = handle_line(&host2, caller, &req_line, &status);
                (resp, is_mut)
            })
            .await
            .map_err(std::io::Error::other)?;
            if mutated && resp.ok {
                on_state_change();
            }
            let mut out = serde_json::to_vec(&resp)?;
            out.push(b'\n');
            w.write_all(&out).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Protector, StateFile};
    use std::io;

    struct Plain;
    impl Protector for Plain {
        fn protect(&self, p: &[u8]) -> io::Result<Vec<u8>> {
            Ok(p.to_vec())
        }
        fn unprotect(&self, s: &[u8]) -> io::Result<Vec<u8>> {
            Ok(s.to_vec())
        }
    }

    fn host(dir: &std::path::Path) -> Mutex<Host> {
        Mutex::new(Host::open(StateFile::new(dir.join("s.bin"), Box::new(Plain))).unwrap())
    }

    const ADMIN: Caller = Caller { admin: true, session: 1 };
    const USER: Caller = Caller { admin: false, session: 1 };

    fn call(h: &Mutex<Host>, c: Caller, line: &str) -> Response {
        handle_line(h, c, line.as_bytes(), &json!({"agent": "running"}))
    }

    #[test]
    fn status_is_open_changes_need_admin() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        let s = call(&h, USER, r#"{"id":1,"method":"status"}"#);
        assert!(s.ok);
        let r = s.result.unwrap();
        assert_eq!(r["registered"], false);
        assert_eq!(r["live"]["agent"], "running");
        for m in MUTATING {
            let resp = call(&h, USER, &format!(r#"{{"id":2,"method":"{m}","params":{{}}}}"#));
            assert_eq!(resp.error.unwrap().code, "forbidden", "{m}");
        }
    }

    #[test]
    fn registration_flow() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        let signed = call(&h, ADMIN, r#"{"id":1,"method":"sign_registration","params":{"nonce":"n","userSub":"u1","kind":"host"}}"#);
        let pk = signed.result.unwrap()["publicKey"].as_str().unwrap().to_string();
        let done = call(
            &h,
            ADMIN,
            r#"{"id":2,"method":"complete_registration","params":{"serverUrl":"https://remote.moonl.cloud","deviceId":"d1","userSub":"u1","name":"PC","deviceToken":"mrdd_abc","rosterKey":"AAAA","rosterKeyId":"k1"}}"#,
        );
        assert!(done.ok, "{done:?}");
        let s = call(&h, USER, r#"{"id":3,"method":"status"}"#).result.unwrap();
        assert_eq!(s["registered"], true);
        assert_eq!(s["deviceId"], "d1");
        assert_eq!(s["publicKey"], pk.as_str());
        assert!(!serde_json::to_string(&s).unwrap().contains("mrdd_"), "status must not reveal the device token");
    }

    #[test]
    fn pin_and_lan_and_bad_input() {
        let dir = tempfile::tempdir().unwrap();
        let h = host(dir.path());
        assert_eq!(call(&h, ADMIN, r#"{"id":1,"method":"set_pin","params":{"pin":"123456"}}"#).error.unwrap().code, "bad_pin");
        assert!(call(&h, ADMIN, r#"{"id":2,"method":"set_pin","params":{"pin":"482916"}}"#).ok);
        assert!(call(&h, ADMIN, r#"{"id":3,"method":"set_lan_direct","params":{"enabled":true}}"#).ok);
        let s = call(&h, USER, r#"{"id":4,"method":"status"}"#).result.unwrap();
        assert_eq!((s["pinSet"].clone(), s["lanDirect"].clone()), (json!(true), json!(true)));

        assert_eq!(call(&h, ADMIN, "not json").error.unwrap().code, "bad_request");
        assert_eq!(call(&h, ADMIN, r#"{"id":5,"method":"nope"}"#).error.unwrap().code, "unknown_method");
        assert_eq!(
            call(&h, ADMIN, r#"{"id":6,"method":"set_pin","params":{"pin":"482916","extra":1}}"#).error.unwrap().code,
            "bad_request",
            "unknown fields are rejected"
        );
        assert_eq!(
            call(&h, ADMIN, r#"{"id":7,"method":"complete_registration","params":{"serverUrl":"x","deviceId":"d","userSub":"u","name":"n","deviceToken":"nope","rosterKey":"","rosterKeyId":""}}"#)
                .error
                .unwrap()
                .code,
            "bad_request"
        );
    }
}
