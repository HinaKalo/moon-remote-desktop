//! HTTP client for `moon-remote-server` authenticated with the host's device token.
//!
//! Endpoints used by the host service (see `docs/server-api.md`):
//! * `GET /v1/devices`: account devices and their Ed25519 keys for the QUIC allow list.
//! * `POST /v1/et/credential`: short-lived EasyTier credential, peers and virtual IPv4.
//! * `POST /v1/signal/ticket`: single-use ticket for the signalling WebSocket.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroize;

/// Device entry returned by `GET /v1/devices`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub public_key: String,
    #[serde(default)]
    pub online: bool,
    #[serde(rename = "self", default)]
    pub is_self: bool,
}

#[derive(Deserialize)]
struct DevicesResponse {
    devices: Vec<DeviceView>,
}

/// Grant returned by `POST /v1/et/credential`.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EtGrant {
    pub network_name: String,
    pub credential: String,
    pub expires_at: String,
    pub peers: Vec<String>,
    pub ipv4: String,
}

impl std::fmt::Debug for EtGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtGrant")
            .field("network_name", &self.network_name)
            .field("expires_at", &self.expires_at)
            .field("peers", &self.peers)
            .field("ipv4", &self.ipv4)
            .finish_non_exhaustive()
    }
}

impl Drop for EtGrant {
    fn drop(&mut self) {
        self.credential.zeroize();
    }
}

/// Minimum delay before renewing a credential, so a clock skew or very short TTL never
/// tight-loops.
const MIN_RENEW_DELAY: Duration = Duration::from_secs(30);
/// Fallback renewal interval when `expiresAt` cannot be parsed.
const FALLBACK_RENEW_DELAY: Duration = Duration::from_secs(12 * 3600);

impl EtGrant {
    /// Extracts the host's virtual IPv4 address (stripping the `/24` prefix length).
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        let ip = self.ipv4.split('/').next()?;
        ip.parse().ok()
    }

    /// Parses `expires_at` (RFC 3339) into a `SystemTime`.
    pub fn expires_time(&self) -> Option<SystemTime> {
        let dt = OffsetDateTime::parse(&self.expires_at, &Rfc3339).ok()?;
        let secs = dt.unix_timestamp();
        let nanos = dt.nanosecond();
        if secs < 0 {
            return None;
        }
        Some(UNIX_EPOCH + Duration::new(secs as u64, nanos))
    }

    /// How long to wait before renewing this credential (75% of remaining lifetime,
    /// floored at 30 s).
    pub fn renew_after(&self, now: SystemTime) -> Duration {
        let Some(exp) = self.expires_time() else {
            return FALLBACK_RENEW_DELAY;
        };
        let Ok(remaining) = exp.duration_since(now) else {
            return MIN_RENEW_DELAY;
        };
        let target = remaining.mul_f64(0.75);
        target.max(MIN_RENEW_DELAY)
    }
}

/// Ticket returned by `POST /v1/signal/ticket`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignalTicket {
    pub ticket: String,
    pub expires_at: String,
}

#[derive(Deserialize)]
struct ServerErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// HTTP 401: the device token was revoked or the device was deleted.
    #[error("device token rejected by server (401)")]
    Unauthorized,
    /// HTTP 503: EasyTier is not configured on the server.
    #[error("server reported service unavailable: {0}")]
    Unavailable(String),
    /// HTTP 409: subnet conflict or no free address.
    #[error("server conflict ({code}): {message}")]
    Conflict { code: String, message: String },
    #[error("server returned HTTP {status}: {message}")]
    Http { status: u16, code: String, message: String },
    #[error("invalid server URL: {0}")]
    BadUrl(String),
    #[error("network error: {0}")]
    Transport(String),
}

/// Authenticated client for one host registration.
#[derive(Clone)]
pub struct ServerClient {
    base_url: String,
    http: Client,
}

impl ServerClient {
    pub fn new(server_url: &str, device_token: &str) -> Result<Self, ApiError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let base_url = server_url.trim_end_matches('/').to_string();
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(ApiError::BadUrl(server_url.into()));
        }
        let mut headers = HeaderMap::new();
        let auth = HeaderValue::from_str(&format!("Device {device_token}"))
            .map_err(|e| ApiError::BadUrl(format!("invalid device token header: {e}")))?;
        headers.insert(AUTHORIZATION, auth);
        let http = Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Ok(Self { base_url, http })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn signal_ws_url(&self, ticket: &str) -> Result<String, ApiError> {
        signal_ws_url(&self.base_url, ticket)
    }

    pub async fn ice_servers(&self) -> Result<Vec<webrtc::ice_transport::ice_server::RTCIceServer>, ApiError> {
        #[derive(Deserialize)]
        struct Server { urls: Vec<String>, #[serde(default)] username: String, #[serde(default)] credential: String }
        #[derive(Deserialize)]
        struct Ice { #[serde(rename = "iceServers")] servers: Vec<Server> }
        let resp = self.http.get(format!("{}/v1/turn", self.base_url)).send().await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        if resp.status() == StatusCode::SERVICE_UNAVAILABLE { return Ok(vec![]); }
        let ice: Ice = decode_response(resp).await?;
        Ok(ice.servers.into_iter().map(|s| webrtc::ice_transport::ice_server::RTCIceServer {
            urls: s.urls, username: s.username, credential: s.credential,
        }).collect())
    }

    /// `GET /v1/devices`
    pub async fn list_devices(&self) -> Result<Vec<DeviceView>, ApiError> {
        let resp = self
            .http
            .get(format!("{}/v1/devices", self.base_url))
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let parsed: DevicesResponse = decode_response(resp).await?;
        Ok(parsed.devices)
    }

    /// `POST /v1/et/credential`
    pub async fn request_et_credential(&self, occupied: &[String]) -> Result<EtGrant, ApiError> {
        #[derive(Serialize)]
        struct Body<'a> {
            occupied: &'a [String],
        }
        let resp = self
            .http
            .post(format!("{}/v1/et/credential", self.base_url))
            .json(&Body { occupied })
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }

    /// `POST /v1/signal/ticket`
    pub async fn request_signal_ticket(&self) -> Result<SignalTicket, ApiError> {
        let resp = self
            .http
            .post(format!("{}/v1/signal/ticket", self.base_url))
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }

    /// `GET /v1/roster` — signed account device roster for offline LAN direct mode.
    pub async fn fetch_roster(&self) -> Result<crate::roster::SignedRoster, ApiError> {
        let resp = self
            .http
            .get(format!("{}/v1/roster", self.base_url))
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }
}

async fn decode_response<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T, ApiError> {
    let status = resp.status();
    if status.is_success() {
        return resp.json::<T>().await.map_err(|e| ApiError::Transport(format!("invalid json: {e}")));
    }
    let body = resp.text().await.unwrap_or_default();
    let parsed = serde_json::from_str::<ServerErrorBody>(&body).ok();
    let code = parsed.as_ref().map(|p| p.error.clone()).unwrap_or_default();
    let message = parsed
        .as_ref()
        .map(|p| if p.message.is_empty() { body.clone() } else { p.message.clone() })
        .unwrap_or(body);
    match status {
        StatusCode::UNAUTHORIZED => Err(ApiError::Unauthorized),
        StatusCode::SERVICE_UNAVAILABLE => Err(ApiError::Unavailable(message)),
        StatusCode::CONFLICT => Err(ApiError::Conflict { code, message }),
        other => Err(ApiError::Http { status: other.as_u16(), code, message }),
    }
}

/// Converts an HTTP(S) server base URL into the WebSocket URL for `/v1/signal?ticket=…`.
pub fn signal_ws_url(server_url: &str, ticket: &str) -> Result<String, ApiError> {
    let trimmed = server_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(ApiError::BadUrl(server_url.into()));
    };
    Ok(format!("{ws_base}/v1/signal?ticket={ticket}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn mock_server(status: &'static str, body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn ws_url_conversion() {
        assert_eq!(signal_ws_url("https://remote.moonl.cloud/", "t1").unwrap(), "wss://remote.moonl.cloud/v1/signal?ticket=t1");
        assert_eq!(signal_ws_url("http://127.0.0.1:8621", "t2").unwrap(), "ws://127.0.0.1:8621/v1/signal?ticket=t2");
        assert!(signal_ws_url("ftp://example.com", "t").is_err());
    }

    #[test]
    fn grant_ipv4_and_renew_delay() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // 1000 s after `now` = 2023-11-14T22:30:00Z -> 75% is 750 s.
        let exp = OffsetDateTime::from_unix_timestamp(1_700_001_000).unwrap();
        let g = EtGrant {
            network_name: "mrd-1".into(),
            credential: "secret".into(),
            expires_at: format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                exp.year(),
                exp.month() as u8,
                exp.day(),
                exp.hour(),
                exp.minute(),
                exp.second()
            ),
            peers: vec!["tcp://remote.moonl.cloud:21017".into()],
            ipv4: "10.250.17.3/24".into(),
        };
        assert_eq!(g.ipv4_addr(), Some(Ipv4Addr::new(10, 250, 17, 3)));
        assert_eq!(g.renew_after(now), Duration::from_secs(750));
        // Already expired -> clamped to MIN_RENEW_DELAY.
        assert_eq!(g.renew_after(now + Duration::from_secs(2000)), MIN_RENEW_DELAY);
    }

    #[tokio::test]
    async fn client_sends_device_header_and_handles_responses() {
        let (url, req_task) = mock_server(
            "200 OK",
            r#"{"devices":[{"id":"d1","name":"Office","kind":"host","publicKey":"AAAA","online":true,"self":true}]}"#,
        )
        .await;
        let client = ServerClient::new(&url, "mrdd_tok123").unwrap();
        let devices = client.list_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, "d1");
        assert!(devices[0].is_self);
        let raw_req = req_task.await.unwrap();
        assert!(raw_req.contains("authorization: Device mrdd_tok123") || raw_req.contains("Authorization: Device mrdd_tok123"));

        let (url401, _) = mock_server("401 Unauthorized", r#"{"error":"unauthenticated","message":"revoked"}"#).await;
        let c401 = ServerClient::new(&url401, "mrdd_dead").unwrap();
        assert!(matches!(c401.request_signal_ticket().await, Err(ApiError::Unauthorized)));

        let (url503, _) = mock_server("503 Service Unavailable", r#"{"error":"et_unavailable","message":"not configured"}"#).await;
        let c503 = ServerClient::new(&url503, "mrdd_ok").unwrap();
        assert!(matches!(c503.request_et_credential(&[]).await, Err(ApiError::Unavailable(_))));
    }
}
