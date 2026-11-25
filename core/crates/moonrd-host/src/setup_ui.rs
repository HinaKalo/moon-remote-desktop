//! Tiny loopback HTTP setup & status wizard for `moonrd-host`.
//!
//! Runs on `127.0.0.1:<port>` so the lightweight host plugin needs zero GUI framework
//! dependencies while still offering a clean one-click Moon SSO sign-in, PIN setup,
//! auto-start toggle, and live status dashboard in the user's browser.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use moonrd_service::network::NetworkStatus;
use moonrd_service::state::{Host, Registration};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::autostart;

const SSO_ISSUER: &str = "https://sso.moonl.cloud";
const DESKTOP_CLIENT_ID: &str = "ms_PTyfu8NoBmsYspSFmqdu";
const SERVER_URL: &str = "https://remote.moonl.cloud";

#[derive(Default)]
struct SsoState {
    verifier: Option<String>,
    state: Option<String>,
    dpop_seed: Option<[u8; 32]>,
    access_token: Option<String>,
    user_sub: Option<String>,
    display_name: Option<String>,
}

fn dpop_jkt(sk: &SigningKey) -> String {
    let x = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn create_dpop_proof(sk: &SigningKey, htm: &str, htu: &str, nonce: Option<&str>) -> String {
    let x = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x }
    });
    let mut jti_raw = [0u8; 16];
    OsRng.fill_bytes(&mut jti_raw);
    let jti = URL_SAFE_NO_PAD.encode(jti_raw);
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut payload = json!({ "jti": jti, "htm": htm, "htu": htu, "iat": iat });
    if let Some(n) = nonce {
        payload["nonce"] = json!(n);
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes())
    );
    let sig = sk.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

pub struct SetupContext {
    pub host: Arc<Mutex<Host>>,
    pub net_status: watch::Receiver<NetworkStatus>,
    pub reload_tx: watch::Sender<u64>,
    pub exe_path: PathBuf,
    pub port: u16,
    sso: Mutex<SsoState>,
}

impl SetupContext {
    pub fn new(
        host: Arc<Mutex<Host>>,
        net_status: watch::Receiver<NetworkStatus>,
        reload_tx: watch::Sender<u64>,
        exe_path: PathBuf,
        port: u16,
    ) -> Self {
        Self { host, net_status, reload_tx, exe_path, port, sso: Mutex::new(SsoState::default()) }
    }
}

pub async fn serve(listener: TcpListener, ctx: Arc<SetupContext>, mut shutdown: watch::Receiver<bool>) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            r = listener.accept() => match r {
                Ok(pair) => pair,
                Err(_) => continue,
            },
        };
        let (mut sock, _) = accepted;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            let Ok(n) = sock.read(&mut buf).await else { return };
            if n == 0 {
                return;
            }
            let raw = String::from_utf8_lossy(&buf[..n]);
            let (status, content_type, body) = handle_http(&raw, &ctx).await;
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
        });
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.to_string(), url_decode(v)))
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

async fn handle_http(raw: &str, ctx: &SetupContext) -> (&'static str, &'static str, String) {
    let first = raw.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");

    match (method, path) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", HTML_PAGE.to_string()),
        ("GET", "/api/status") => {
            let h = ctx.host.lock().unwrap_or_else(|e| e.into_inner());
            let sso = ctx.sso.lock().unwrap_or_else(|e| e.into_inner());
            let net = ctx.net_status.borrow().clone();
            let reg = h.state.registration.as_ref();
            let default_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "My-PC".into());
            let data = json!({
                "registered": reg.is_some(),
                "deviceId": reg.map(|r| r.device_id.clone()),
                "hostName": reg.map(|r| r.name.clone()).unwrap_or(default_name),
                "pinSet": h.state.pin.is_some(),
                "autoStart": autostart::is_enabled(),
                "signedIn": sso.access_token.is_some(),
                "displayName": sso.display_name,
                "network": net,
            });
            ("200 OK", "application/json", data.to_string())
        }
        ("GET", "/auth/start") => {
            let mut rnd = [0u8; 32];
            OsRng.fill_bytes(&mut rnd);
            let verifier = URL_SAFE_NO_PAD.encode(rnd);
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            let mut st = [0u8; 16];
            OsRng.fill_bytes(&mut st);
            let state = URL_SAFE_NO_PAD.encode(st);
            let dpop_sk = SigningKey::generate(&mut OsRng);
            let jkt = dpop_jkt(&dpop_sk);
            let redirect_uri = format!("http://127.0.0.1:{}/callback", ctx.port);
            {
                let mut sso = ctx.sso.lock().unwrap_or_else(|e| e.into_inner());
                sso.verifier = Some(verifier);
                sso.state = Some(state.clone());
                sso.dpop_seed = Some(dpop_sk.to_bytes());
            }
            let url = format!(
                "{SSO_ISSUER}/oauth/authorize?response_type=code&client_id={DESKTOP_CLIENT_ID}&redirect_uri={}&scope={}&resource={}&code_challenge={challenge}&code_challenge_method=S256&dpop_jkt={jkt}&state={state}",
                url_encode(&redirect_uri),
                url_encode("openid profile offline_access"),
                url_encode(SERVER_URL),
            );
            ("200 OK", "application/json", json!({"url": url}).to_string())
        }
        ("GET", "/callback") => {
            let q = parse_query(query);
            let code = q.get("code").cloned().unwrap_or_default();
            let state = q.get("state").cloned().unwrap_or_default();
            let (verifier, dpop_seed) = {
                let mut sso = ctx.sso.lock().unwrap_or_else(|e| e.into_inner());
                if sso.state.as_deref() != Some(state.as_str()) || code.is_empty() {
                    return ("400 Bad Request", "text/html; charset=utf-8", "<h3>登录校验失败，请重试</h3>".into());
                }
                (sso.verifier.take().unwrap_or_default(), sso.dpop_seed.unwrap_or([0u8; 32]))
            };
            let redirect_uri = format!("http://127.0.0.1:{}/callback", ctx.port);
            match exchange_token(&code, &verifier, &redirect_uri, &SigningKey::from_bytes(&dpop_seed)).await {
                Ok((tok, sub, name)) => {
                    let mut sso = ctx.sso.lock().unwrap_or_else(|e| e.into_inner());
                    sso.access_token = Some(tok);
                    sso.user_sub = Some(sub);
                    sso.display_name = Some(name);
                    (
                        "200 OK",
                        "text/html; charset=utf-8",
                        "<html><head><meta http-equiv='refresh' content='0;url=/'></head><body>登录成功，正在返回...</body></html>".into(),
                    )
                }
                Err(e) => ("500 Internal Server Error", "text/html; charset=utf-8", format!("<h3>登录失败：{e}</h3>")),
            }
        }
        ("POST", "/api/enable") => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Req {
                host_name: String,
                pin: String,
                auto_start: bool,
            }
            let req: Req = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return ("400 Bad Request", "application/json", json!({"error": e.to_string()}).to_string()),
            };
            let (token, user_sub) = {
                let sso = ctx.sso.lock().unwrap_or_else(|e| e.into_inner());
                match (&sso.access_token, &sso.user_sub) {
                    (Some(t), Some(s)) => (t.clone(), s.clone()),
                    _ => return ("401 Unauthorized", "application/json", json!({"error": "请先使用 Moon 账号登录"}).to_string()),
                }
            };
            match enable_host(ctx, &token, &user_sub, req.host_name.trim(), &req.pin, req.auto_start).await {
                Ok(()) => ("200 OK", "application/json", json!({"ok": true}).to_string()),
                Err(e) => ("400 Bad Request", "application/json", json!({"error": e}).to_string()),
            }
        }
        ("POST", "/api/unregister") => {
            let _ = autostart::set_enabled(&ctx.exe_path, false);
            let res = ctx.host.lock().unwrap_or_else(|e| e.into_inner()).unregister();
            ctx.reload_tx.send_modify(|n| *n = n.wrapping_add(1));
            match res {
                Ok(()) => ("200 OK", "application/json", json!({"ok": true}).to_string()),
                Err(e) => ("500 Internal Server Error", "application/json", json!({"error": e.to_string()}).to_string()),
            }
        }
        _ => ("404 Not Found", "text/plain", "not found".into()),
    }
}

async fn exchange_token(code: &str, verifier: &str, redirect_uri: &str, dpop_sk: &SigningKey) -> Result<(String, String, String), String> {
    let http = reqwest::Client::new();
    let token_url = format!("{SSO_ISSUER}/oauth/token");
    let mut nonce: Option<String> = None;
    let mut resp = None;
    for attempt in 0..2 {
        let proof = create_dpop_proof(dpop_sk, "POST", &token_url, nonce.as_deref());
        let r = http
            .post(&token_url)
            .header("DPoP", proof)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", DESKTOP_CLIENT_ID),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
                ("resource", SERVER_URL),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if r.status() == reqwest::StatusCode::BAD_REQUEST
            && attempt == 0
            && let Some(n) = r.headers().get("DPoP-Nonce").and_then(|v| v.to_str().ok())
        {
            nonce = Some(n.to_string());
            continue;
        }
        resp = Some(r);
        break;
    }
    let resp = resp.ok_or("no token response")?;
    if !resp.status().is_success() {
        return Err(format!("token HTTP {}", resp.status()));
    }
    let tok: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let access = tok["access_token"].as_str().ok_or("missing access_token")?.to_string();
    let ui = http
        .get(format!("{SSO_ISSUER}/oauth/userinfo"))
        .bearer_auth(&access)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())?;
    let sub = ui["sub"].as_str().ok_or("missing sub")?.to_string();
    let name = ui["name"]
        .as_str()
        .or_else(|| ui["preferred_username"].as_str())
        .unwrap_or(&sub)
        .to_string();
    Ok((access, sub, name))
}

async fn enable_host(
    ctx: &SetupContext,
    access_token: &str,
    user_sub: &str,
    host_name: &str,
    pin: &str,
    auto_start: bool,
) -> Result<(), String> {
    // Validate PIN first before talking to server.
    moonrd_session::pin::PinVerifier::create(pin).map_err(|e| format!("PIN 无效: {e}"))?;

    let http = reqwest::Client::new();
    let chal: serde_json::Value = http
        .post(format!("{SERVER_URL}/v1/devices/challenge"))
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let nonce = chal["nonce"].as_str().ok_or("missing nonce")?;

    let (public_key, signature) = ctx
        .host
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .sign_registration(nonce, user_sub, "host")
        .map_err(|e| e.to_string())?;

    let reg_resp: serde_json::Value = http
        .post(format!("{SERVER_URL}/v1/devices"))
        .bearer_auth(access_token)
        .json(&json!({
            "name": if host_name.is_empty() { "My-PC" } else { host_name },
            "kind": "host",
            "publicKey": public_key,
            "nonce": nonce,
            "signature": signature,
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;

    let reg = Registration {
        server_url: SERVER_URL.into(),
        device_id: reg_resp["device"]["id"].as_str().ok_or("missing device.id")?.into(),
        user_sub: user_sub.into(),
        name: reg_resp["device"]["name"].as_str().unwrap_or(host_name).into(),
        device_token: reg_resp["deviceToken"].as_str().ok_or("missing deviceToken")?.into(),
        roster_key: reg_resp["rosterKey"].as_str().unwrap_or("").into(),
        roster_key_id: reg_resp["rosterKeyId"].as_str().unwrap_or("").into(),
    };

    {
        let mut h = ctx.host.lock().unwrap_or_else(|e| e.into_inner());
        h.complete_registration(reg).map_err(|e| e.to_string())?;
        h.set_pin(pin).map_err(|e| e.to_string())?;
    }
    autostart::set_enabled(&ctx.exe_path, auto_start).map_err(|e| format!("设置开机自启失败: {e}"))?;
    ctx.reload_tx.send_modify(|n| *n = n.wrapping_add(1));
    Ok(())
}

const HTML_PAGE: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Moon Remote 被控端主机设置</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0f1117; color: #eef1f7; margin: 0; padding: 32px 16px; }
  .wrap { max-width: 520px; margin: 0 auto; background: #171a24; border: 1px solid #262b3b; border-radius: 14px; padding: 24px; }
  h1 { margin: 0 0 8px; font-size: 20px; }
  p { color: #94a0b8; font-size: 14px; line-height: 1.6; }
  label { display: block; font-size: 13px; color: #cbd5e1; margin: 14px 0 6px; }
  input[type=text], input[type=password] { width: 100%; box-sizing: border-box; background: #0f1117; border: 1px solid #262b3b; color: #fff; padding: 10px 12px; border-radius: 8px; font-size: 14px; }
  .row { display: flex; align-items: center; gap: 10px; margin-top: 16px; }
  button { background: #3b82f6; color: #fff; border: none; padding: 10px 16px; border-radius: 8px; font-weight: 600; cursor: pointer; }
  button.ghost { background: transparent; border: 1px solid #262b3b; color: #eef1f7; }
  .badge { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 12px; border: 1px solid #262b3b; color: #22c55e; }
  #msg { margin-top: 14px; font-size: 13px; color: #fbbf24; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Moon Remote 轻量被控端</h1>
  <p>仅用于共享当前电脑供您的 Moon 账号远程控制，自动随系统开机后台运行。</p>
  <div id="status">加载状态中...</div>
  <div id="auth-box" style="margin-top:16px"></div>
  <div id="form-box" style="display:none">
    <label>主机名称</label>
    <input id="hostName" type="text" />
    <label>连接 PIN（6–12 位数字，仅保存在本机加密存储）</label>
    <input id="pin" type="password" inputmode="numeric" placeholder="例如 482916" />
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
      <input id="autoStart" type="checkbox" checked /> 开机自动启动（后台运行）
    </label>
    <div class="row">
      <button id="btn-enable">启用并共享此主机</button>
      <button id="btn-unreg" class="ghost" style="display:none">停止共享</button>
    </div>
  </div>
  <div id="msg"></div>
</div>
<script>
async function refresh() {
  const s = await (await fetch('/api/status')).json();
  const sig = s.network?.signal?.state || 'disconnected';
  const et = s.network?.et?.state || 'stopped';
  document.getElementById('status').innerHTML = s.registered
    ? `<span class="badge">已启用共享</span> 主机 ID: <code>${s.deviceId}</code> · 信令: ${sig} · EasyTier: ${et} · 开机自启: ${s.autoStart ? '是' : '否'}`
    : `尚未启用远程共享`;
  document.getElementById('hostName').value = s.hostName || '';
  document.getElementById('autoStart').checked = s.registered ? !!s.autoStart : true;
  document.getElementById('btn-unreg').style.display = s.registered ? 'inline-block' : 'none';
  if (s.signedIn) {
    document.getElementById('auth-box').innerHTML = `已登录 Moon 账号：<strong>${s.displayName}</strong>`;
    document.getElementById('form-box').style.display = 'block';
  } else {
    document.getElementById('auth-box').innerHTML = `<button id="btn-sso">使用 Moon SSO 登录</button>`;
    document.getElementById('btn-sso').onclick = async () => {
      const r = await (await fetch('/auth/start')).json();
      location.href = r.url;
    };
    document.getElementById('form-box').style.display = s.registered ? 'block' : 'none';
  }
}
document.getElementById('btn-enable').onclick = async () => {
  const msg = document.getElementById('msg');
  msg.textContent = '正在注册主机并启用共享...';
  const resp = await fetch('/api/enable', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      hostName: document.getElementById('hostName').value,
      pin: document.getElementById('pin').value,
      autoStart: document.getElementById('autoStart').checked,
    })
  });
  const data = await resp.json();
  if (resp.ok) {
    msg.textContent = '已启用！现在可以关闭此页，并在 https://remote.moonl.cloud 中连接此主机。';
    document.getElementById('pin').value = '';
    refresh();
  } else {
    msg.textContent = data.error || '启用失败';
  }
};
document.getElementById('btn-unreg').onclick = async () => {
  await fetch('/api/unregister', { method: 'POST' });
  document.getElementById('msg').textContent = '已停止共享并关闭开机自启。';
  refresh();
};
refresh();
setInterval(refresh, 4000);
</script>
</body>
</html>
"#;
