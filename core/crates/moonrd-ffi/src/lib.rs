//! C ABI (`moonrd_ffi.dll`) for the C# Lumen desktop application.
//!
//! Follows the 3-function JSON model:
//! * `moonrd_init()` — initializes runtime & Media Foundation.
//! * `moonrd_call(json)` — runs a command and returns a JSON response string.
//! * `moonrd_next_event(timeout_ms)` — polls the next asynchronous viewer event JSON.
//! * `moonrd_free_str(ptr)` — frees any string returned by this library.
//! * `moonrd_shutdown()` — stops active sessions and cleans up.

mod viewer;

use std::ffi::{CStr, CString, c_char};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use moonrd_proto::envelope::Msg;
use moonrd_proto::{ClipboardData, Envelope, KeyEvent, PointerButton, PointerEvent, SelectDisplay, SpecialAction, SpecialActionKind};
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::{Value, json};
use moonrd_session::release::RelhubManifest;
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;

use crate::viewer::{ConnectParams, ViewerCmd};

struct EngineState {
    rt: Runtime,
    event_tx: Sender<Value>,
    event_rx: Mutex<Receiver<Value>>,
    active_cmd: Mutex<Option<tokio_mpsc::Sender<ViewerCmd>>>,
}

static STATE: OnceLock<EngineState> = OnceLock::new();

fn state() -> Option<&'static EngineState> {
    STATE.get()
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_else(|_| CString::new("{}").unwrap()).into_raw()
}

fn ok_json(result: Value) -> String {
    json!({"ok": true, "result": result}).to_string()
}

fn err_json(msg: impl Into<String>) -> String {
    json!({"ok": false, "error": msg.into()}).to_string()
}

#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    #[serde(default)]
    params: Value,
}

/// Initializes the FFI runtime and Media Foundation. Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn moonrd_init() -> i32 {
    #[cfg(windows)]
    let _ = moonrd_media::init_media_foundation();
    let res = STATE.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let (event_tx, event_rx) = mpsc::channel();
        EngineState { rt, event_tx, event_rx: Mutex::new(event_rx), active_cmd: Mutex::new(None) }
    });
    let _ = res;
    0
}

/// Executes one JSON command and returns a JSON response string (free with `moonrd_free_str`).
///
/// # Safety
/// `req_json` must be a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moonrd_call(req_json: *const c_char) -> *mut c_char {
    if req_json.is_null() {
        return to_c_string(err_json("null request"));
    }
    let raw = match unsafe { CStr::from_ptr(req_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return to_c_string(err_json("invalid utf-8")),
    };
    let req: RpcRequest = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => return to_c_string(err_json(format!("bad json: {e}"))),
    };
    to_c_string(dispatch(req))
}

/// Waits up to `timeout_ms` for the next event JSON. Returns null on timeout.
#[unsafe(no_mangle)]
pub extern "C" fn moonrd_next_event(timeout_ms: u32) -> *mut c_char {
    let Some(st) = state() else { return std::ptr::null_mut() };
    let rx = st.event_rx.lock().unwrap_or_else(|e| e.into_inner());
    match rx.recv_timeout(Duration::from_millis(timeout_ms as u64)) {
        Ok(ev) => to_c_string(ev.to_string()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a string previously returned by `moonrd_call` or `moonrd_next_event`.
///
/// # Safety
/// `ptr` must be null or a pointer returned by `moonrd_call` / `moonrd_next_event`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moonrd_free_str(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Disconnects any active viewer session.
#[unsafe(no_mangle)]
pub extern "C" fn moonrd_shutdown() {
    if let Some(st) = state()
        && let Some(tx) = st.active_cmd.lock().unwrap_or_else(|e| e.into_inner()).take()
    {
        let _ = tx.try_send(ViewerCmd::Disconnect);
    }
}

fn dispatch(req: RpcRequest) -> String {
    match req.method.as_str() {
        "detect_easytier" => {
            let d = moonrd_et::detect(&[]);
            ok_json(json!({
                "found": d.found(),
                "processes": d.processes.iter().map(|(n, pid)| json!({"name": n, "pid": pid})).collect::<Vec<_>>(),
                "stockRpcPortBusy": d.stock_rpc_port_busy,
                "stockListenerPortBusy": d.stock_listener_port_busy,
            }))
        }
        "generate_device_key" => {
            let sk = SigningKey::generate(&mut OsRng);
            ok_json(json!({
                "seed": B64.encode(sk.to_bytes()),
                "publicKey": B64.encode(sk.verifying_key().to_bytes()),
            }))
        }
        "sign_registration" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct P {
                seed: String,
                nonce: String,
                user_sub: String,
                kind: String,
            }
            let p: P = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            let seed: [u8; 32] = match B64.decode(&p.seed).ok().and_then(|b| b.try_into().ok()) {
                Some(s) => s,
                None => return err_json("invalid seed"),
            };
            let sk = SigningKey::from_bytes(&seed);
            let public = B64.encode(sk.verifying_key().to_bytes());
            let msg = format!("moonrd/device-register/v1\n{}\n{}\n{}\n{public}", p.nonce, p.user_sub, p.kind);
            let sig = B64.encode(sk.sign(msg.as_bytes()).to_bytes());
            ok_json(json!({"publicKey": public, "signature": sig}))
        }
        "connect" => {
            let Some(st) = state() else { return err_json("not initialized") };
            let params: ConnectParams = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            let (tx, rx) = tokio_mpsc::channel(128);
            if let Some(prev) = st.active_cmd.lock().unwrap_or_else(|e| e.into_inner()).replace(tx) {
                let _ = prev.try_send(ViewerCmd::Disconnect);
            }
            let ev_tx = st.event_tx.clone();
            st.rt.spawn(viewer::run_session(params, rx, ev_tx));
            ok_json(json!({}))
        }
        "submit_pin" => {
            #[derive(Deserialize)]
            struct P {
                pin: String,
                #[serde(default)]
                remember: bool,
                #[serde(default)]
                label: String,
            }
            let p: P = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            send_cmd(ViewerCmd::SubmitPin { pin: p.pin, remember: p.remember, label: p.label })
        }
        "send_pointer" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct P {
                #[serde(default = "one")]
                display_id: u32,
                x: u32,
                y: u32,
                #[serde(default)]
                button: i32,
                #[serde(default)]
                pressed: bool,
                #[serde(default)]
                wheel_x: i32,
                #[serde(default)]
                wheel_y: i32,
            }
            fn one() -> u32 { 1 }
            let p: P = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            let btn = PointerButton::try_from(p.button).unwrap_or(PointerButton::None) as i32;
            send_cmd(ViewerCmd::Send(Envelope {
                msg: Some(Msg::Pointer(PointerEvent {
                    display_id: p.display_id,
                    x: p.x,
                    y: p.y,
                    button: btn,
                    pressed: p.pressed,
                    wheel_x: p.wheel_x,
                    wheel_y: p.wheel_y,
                })),
            }))
        }
        "send_key" => {
            #[derive(Deserialize)]
            struct P {
                #[serde(default)]
                scancode: u32,
                #[serde(default)]
                extended: bool,
                #[serde(default)]
                pressed: bool,
                #[serde(default)]
                text: String,
            }
            let p: P = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            send_cmd(ViewerCmd::Send(Envelope {
                msg: Some(Msg::Key(KeyEvent {
                    scancode: p.scancode,
                    extended: p.extended,
                    pressed: p.pressed,
                    lock_state: 0,
                    text: p.text,
                })),
            }))
        }
        "send_clipboard" => {
            #[derive(Deserialize)]
            struct P {
                text: String,
            }
            let p: P = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            send_cmd(ViewerCmd::Send(Envelope { msg: Some(Msg::Clipboard(ClipboardData { text: p.text })) }))
        }
        "send_special" => {
            #[derive(Deserialize)]
            struct P {
                kind: String,
            }
            let p: P = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            let kind = match p.kind.as_str() {
                "ctrl_alt_del" => SpecialActionKind::SpecialActionCtrlAltDel,
                "lock" => SpecialActionKind::SpecialActionLockWorkstation,
                "block_input" => SpecialActionKind::SpecialActionBlockLocalInput,
                "unblock_input" => SpecialActionKind::SpecialActionUnblockLocalInput,
                other => return err_json(format!("unknown special action: {other}")),
            };
            send_cmd(ViewerCmd::Send(Envelope { msg: Some(Msg::SpecialAction(SpecialAction { kind: kind as i32 })) }))
        }
        "select_display" => {
            #[derive(Deserialize)]
            struct P {
                id: u32,
            }
            let p: P = match serde_json::from_value(req.params) {
                Ok(p) => p,
                Err(e) => return err_json(e.to_string()),
            };
            send_cmd(ViewerCmd::Send(Envelope { msg: Some(Msg::SelectDisplay(SelectDisplay { id: p.id })) }))
        }
        "disconnect" => {
            moonrd_shutdown();
            ok_json(json!({}))
        }
        "verify_relhub_manifest" => verify_relhub_manifest_cmd(req.params),
        other => err_json(format!("unknown method: {other}")),
    }
}

fn verify_relhub_manifest_cmd(params: Value) -> String {
    let m: RelhubManifest = match serde_json::from_value(params) {
        Ok(m) => m,
        Err(e) => return err_json(format!("invalid manifest: {e}")),
    };
    match m.verify() {
        Ok(()) => ok_json(json!({"verified": true})),
        Err(e) => err_json(e),
    }
}

fn send_cmd(cmd: ViewerCmd) -> String {
    let Some(st) = state() else { return err_json("not initialized") };
    let guard = st.active_cmd.lock().unwrap_or_else(|e| e.into_inner());
    let motion = matches!(&cmd, ViewerCmd::Send(Envelope { msg: Some(Msg::Pointer(p)) })
        if p.button == 0 && p.wheel_x == 0 && p.wheel_y == 0);
    match guard.as_ref() {
        // Preserve room for clicks and key transitions when the route is slow.
        Some(tx) if motion && tx.capacity() <= 8 => ok_json(json!({})),
        Some(tx) if tx.try_send(cmd).is_ok() => ok_json(json!({})),
        Some(_) => err_json("viewer queue full or closed"),
        None => err_json("no active session"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation_and_registration_signature_work() {
        assert_eq!(moonrd_init(), 0);
        let gen_req = CString::new(r#"{"method":"generate_device_key"}"#).unwrap();
        let resp_ptr = unsafe { moonrd_call(gen_req.as_ptr()) };
        let resp_str = unsafe { CStr::from_ptr(resp_ptr) }.to_str().unwrap().to_string();
        unsafe { moonrd_free_str(resp_ptr) };
        let v: Value = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(v["ok"], true);
        let seed = v["result"]["seed"].as_str().unwrap();

        let sign_req = json!({
            "method": "sign_registration",
            "params": { "seed": seed, "nonce": "n1", "userSub": "u1", "kind": "viewer" }
        })
        .to_string();
        let c_req = CString::new(sign_req).unwrap();
        let s_ptr = unsafe { moonrd_call(c_req.as_ptr()) };
        let s_str = unsafe { CStr::from_ptr(s_ptr) }.to_str().unwrap().to_string();
        unsafe { moonrd_free_str(s_ptr) };
        let sv: Value = serde_json::from_str(&s_str).unwrap();
        assert_eq!(sv["ok"], true);
        assert_eq!(sv["result"]["publicKey"], v["result"]["publicKey"]);
        assert!(!sv["result"]["signature"].as_str().unwrap().is_empty());
    }

}
