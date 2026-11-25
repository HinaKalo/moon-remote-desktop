//! Signalling WebSocket client for presence and incoming session invites.
//!
//! Protocol matches `server/internal/signal/hub.go` and `docs/server-api.md`:
//! 1. Request a single-use ticket via `POST /v1/signal/ticket`.
//! 2. Connect to `GET /v1/signal?ticket=<ticket>`.
//! 3. Receive `welcome`, `presence-snapshot`, `presence`, and relayed messages.
//! 4. On `invite`, refresh the allowed viewer keys and reply with `quic-endpoint`
//!    (`{ipv4, port}`) or `reject` (`{reason}`).

use std::collections::HashSet;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;

use crate::server_api::{ApiError, ServerClient};

const BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const STABLE_AFTER: Duration = Duration::from_secs(15);

/// Server → client message (matches `signal.Outbound` in Go).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outbound {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub from_conn: String,
    #[serde(default)]
    pub from_name: String,
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub data: Option<Value>,
    #[serde(default)]
    pub conn: String,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub online: Option<bool>,
    #[serde(default)]
    pub list: Vec<String>,
    #[serde(default)]
    pub code: String,
}

/// Client → server message (matches `signal.Inbound` in Go).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Inbound {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_conn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Live signalling state exposed via the UI pipe `status`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum SignalStatus {
    Disconnected,
    Connecting,
    Connected {
        #[serde(rename = "connId")]
        conn_id: String,
        #[serde(rename = "onlinePeers")]
        online_peers: usize,
    },
    Revoked,
    Error {
        message: String,
    },
}

/// Decision made by the host when a viewer sends `invite`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteReply {
    /// Host is ready on EasyTier; tell the viewer where to dial QUIC.
    QuicEndpoint { ipv4: Ipv4Addr, port: u16 },
    WebAnswer { sdp: String },
    /// Host cannot accept this invite right now.
    Reject { reason: String },
}

/// Handles incoming `invite` messages from the signalling hub.
pub trait InviteHandler: Send + Sync {
    fn on_invite<'a>(&'a self, invite: &'a Outbound) -> Pin<Box<dyn Future<Output = InviteReply> + Send + 'a>>;
}

/// Builds the reply `Inbound` message for an `invite`, addressing `to` (device id) when
/// available and falling back to `toConn` (web viewers have no device id).
pub fn build_invite_reply(invite: &Outbound, reply: InviteReply) -> Inbound {
    let (to, to_conn) = if !invite.from.is_empty() {
        (Some(invite.from.clone()), None)
    } else {
        (None, Some(invite.from_conn.clone()))
    };
    let session = (!invite.session.is_empty()).then(|| invite.session.clone());
    match reply {
        InviteReply::QuicEndpoint { ipv4, port } => Inbound {
            kind: "quic-endpoint".into(),
            to,
            to_conn,
            session,
            data: Some(json!({ "ipv4": ipv4.to_string(), "port": port })),
        },
        InviteReply::WebAnswer { sdp } => Inbound {
            kind: "sdp".into(), to, to_conn, session,
            data: Some(json!({ "type": "answer", "sdp": sdp })),
        },
        InviteReply::Reject { reason } => Inbound {
            kind: "reject".into(),
            to,
            to_conn,
            session,
            data: Some(json!({ "reason": reason })),
        },
    }
}

fn backoff_delay(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(10);
    (BACKOFF_BASE * 2u32.pow(exp)).min(BACKOFF_MAX)
}

/// Runs the signalling WebSocket loop until `shutdown` resolves or the device token is
/// revoked (HTTP 401).
pub async fn run_loop<H, F>(
    client: ServerClient,
    handler: H,
    status_tx: watch::Sender<SignalStatus>,
    mut shutdown: watch::Receiver<bool>,
    mut log: F,
) where
    H: InviteHandler,
    F: FnMut(&str),
{
    let mut failures = 0u32;

    loop {
        if *shutdown.borrow() {
            break;
        }
        let _ = status_tx.send(SignalStatus::Connecting);
        let ticket = tokio::select! {
            _ = shutdown.changed() => break,
            r = client.request_signal_ticket() => r,
        };
        let ticket = match ticket {
            Ok(t) => t,
            Err(ApiError::Unauthorized) => {
                log("signal: device token rejected (401); stopping");
                let _ = status_tx.send(SignalStatus::Revoked);
                break;
            }
            Err(e) => {
                failures += 1;
                let wait = backoff_delay(failures);
                log(&format!("signal: ticket request failed ({e}); retry in {}s", wait.as_secs()));
                let _ = status_tx.send(SignalStatus::Error { message: e.to_string() });
                if sleep_or_shutdown(wait, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        let ws_url = match client.signal_ws_url(&ticket.ticket) {
            Ok(u) => u,
            Err(e) => {
                let _ = status_tx.send(SignalStatus::Error { message: e.to_string() });
                break;
            }
        };

        let connected_at = Instant::now();
        match run_once(&ws_url, &handler, &status_tx, &mut shutdown, &mut log).await {
            Ok(()) => break, // clean shutdown
            Err(e) => {
                if connected_at.elapsed() >= STABLE_AFTER {
                    failures = 0;
                } else {
                    failures += 1;
                }
                let wait = backoff_delay(failures);
                log(&format!("signal: disconnected ({e}); retry in {}s", wait.as_secs()));
                let _ = status_tx.send(SignalStatus::Error { message: e });
                if sleep_or_shutdown(wait, &mut shutdown).await {
                    break;
                }
            }
        }
    }

    if *status_tx.borrow() != SignalStatus::Revoked {
        let _ = status_tx.send(SignalStatus::Disconnected);
    }
}

/// Runs one WebSocket session. Returns `Ok(())` on shutdown, `Err(reason)` if the
/// connection failed or dropped.
pub async fn run_once<H, F>(
    ws_url: &str,
    handler: &H,
    status_tx: &watch::Sender<SignalStatus>,
    shutdown: &mut watch::Receiver<bool>,
    log: &mut F,
) -> Result<(), String>
where
    H: InviteHandler,
    F: FnMut(&str),
{
    let (ws, _) = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        r = tokio_tungstenite::connect_async(ws_url) => r.map_err(|e| e.to_string())?,
    };
    let (mut sink, mut stream) = ws.split();
    let mut conn_id = String::new();
    let mut online: HashSet<String> = HashSet::new();

    loop {
        let frame = tokio::select! {
            _ = shutdown.changed() => {
                let _ = sink.send(Message::Close(None)).await;
                return Ok(());
            }
            next = stream.next() => match next {
                Some(Ok(m)) => m,
                Some(Err(e)) => return Err(e.to_string()),
                None => return Err("closed by server".into()),
            },
        };

        match frame {
            Message::Text(text) => {
                let msg: Outbound = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        log(&format!("signal: ignoring malformed json: {e}"));
                        continue;
                    }
                };
                match msg.kind.as_str() {
                    "welcome" => {
                        conn_id = msg.conn.clone();
                        log(&format!("signal: connected conn={conn_id}"));
                        let _ = status_tx.send(SignalStatus::Connected { conn_id: conn_id.clone(), online_peers: online.len() });
                    }
                    "presence-snapshot" => {
                        online = msg.list.into_iter().collect();
                        if !conn_id.is_empty() {
                            let _ = status_tx.send(SignalStatus::Connected { conn_id: conn_id.clone(), online_peers: online.len() });
                        }
                    }
                    "presence" => {
                        if let Some(is_on) = msg.online {
                            if is_on {
                                online.insert(msg.device);
                            } else {
                                online.remove(&msg.device);
                            }
                            if !conn_id.is_empty() {
                                let _ = status_tx.send(SignalStatus::Connected { conn_id: conn_id.clone(), online_peers: online.len() });
                            }
                        }
                    }
                    "invite" => {
                        log(&format!("signal: invite session={} from={}", msg.session, if msg.from.is_empty() { &msg.from_conn } else { &msg.from }));
                        let reply = handler.on_invite(&msg).await;
                        let out = build_invite_reply(&msg, reply);
                        let payload = serde_json::to_string(&out).map_err(|e| e.to_string())?;
                        sink.send(Message::Text(payload.into())).await.map_err(|e| e.to_string())?;
                    }
                    "error" => {
                        log(&format!("signal: server error code={} session={}", msg.code, msg.session));
                    }
                    _ => {}
                }
            }
            Message::Ping(data) => {
                sink.send(Message::Pong(data)).await.map_err(|e| e.to_string())?;
            }
            Message::Close(_) => return Err("closed by server".into()),
            _ => {}
        }
    }
}

async fn sleep_or_shutdown(dur: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = shutdown.changed() => true,
        _ = tokio::time::sleep(dur) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    struct StaticHandler(InviteReply);
    impl InviteHandler for StaticHandler {
        fn on_invite<'a>(&'a self, _invite: &'a Outbound) -> Pin<Box<dyn Future<Output = InviteReply> + Send + 'a>> {
            let r = self.0.clone();
            Box::pin(async move { r })
        }
    }

    #[tokio::test]
    async fn handles_welcome_presence_and_invite() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ws.send(Message::Text(r#"{"type":"welcome","conn":"c-1","device":"d-host"}"#.into())).await.unwrap();
            ws.send(Message::Text(r#"{"type":"presence-snapshot","list":["d-viewer"]}"#.into())).await.unwrap();
            ws.send(Message::Text(
                r#"{"type":"invite","from":"d-viewer","fromConn":"c-2","session":"s-9","data":{}}"#.into(),
            ))
            .await
            .unwrap();
            let reply = match ws.next().await.unwrap().unwrap() {
                Message::Text(t) => serde_json::from_str::<Inbound>(&t).unwrap(),
                other => panic!("expected text, got {other:?}"),
            };
            ws.send(Message::Close(None)).await.unwrap();
            reply
        });

        let (status_tx, status_rx) = watch::channel(SignalStatus::Disconnected);
        let (_stop_tx, mut stop_rx) = watch::channel(false);
        let handler = StaticHandler(InviteReply::QuicEndpoint { ipv4: Ipv4Addr::new(10, 250, 17, 3), port: 47000 });
        let url = format!("ws://{addr}/v1/signal?ticket=t");
        let _ = run_once(&url, &handler, &status_tx, &mut stop_rx, &mut |_| {}).await;

        let reply = server_task.await.unwrap();
        assert_eq!(reply.kind, "quic-endpoint");
        assert_eq!(reply.to.as_deref(), Some("d-viewer"));
        assert_eq!(reply.to_conn, None);
        assert_eq!(reply.session.as_deref(), Some("s-9"));
        assert_eq!(reply.data.unwrap(), json!({ "ipv4": "10.250.17.3", "port": 47000 }));
        assert_eq!(*status_rx.borrow(), SignalStatus::Connected { conn_id: "c-1".into(), online_peers: 1 });
    }

    #[test]
    fn web_viewer_invite_replies_with_to_conn() {
        let invite = Outbound {
            kind: "invite".into(),
            from: String::new(),
            from_conn: "c-web".into(),
            from_name: "Alice".into(),
            session: "s-1".into(),
            data: None,
            conn: String::new(),
            device: String::new(),
            online: None,
            list: vec![],
            code: String::new(),
        };
        let reply = build_invite_reply(&invite, InviteReply::Reject { reason: "webrtc not ready".into() });
        assert_eq!(reply.kind, "reject");
        assert_eq!(reply.to, None);
        assert_eq!(reply.to_conn.as_deref(), Some("c-web"));
        assert_eq!(reply.session.as_deref(), Some("s-1"));
    }
}
