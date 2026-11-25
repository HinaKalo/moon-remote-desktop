//! Browser sessions use gathered SDP over account-scoped signalling, then DTLS-bound
//! PIN authentication over the ordered data channel before attaching the capture agent.
use crate::{agent_pipe::{AgentBridge, ViewerAttachment, ViewerInput}, server_api::ServerClient, state::Host};
use moonrd_proto::{Envelope, KeyframeRequest, envelope::Msg};
use moonrd_session::{
    frame,
    handshake::{HostContext, HostHandshake, Outcome},
    lockout::Policy,
    pake::ChannelBinding,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};
use tokio::time::Instant;
use webrtc::{
    api::{
        APIBuilder, interceptor_registry::register_default_interceptors, media_engine::MediaEngine,
    },
    data_channel::RTCDataChannel,
    interceptor::registry::Registry,
    media::Sample,
    peer_connection::{
        configuration::RTCConfiguration, sdp::session_description::RTCSessionDescription,
    },
    ice_transport::ice_server::RTCIceServer,
    rtcp::payload_feedbacks::{full_intra_request::FullIntraRequest, picture_loss_indication::PictureLossIndication},
    rtp_transceiver::{rtp_codec::RTCRtpCodecCapability, rtp_sender::RTCRtpSender},
    track::track_local::track_local_static_sample::TrackLocalStaticSample,
};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn fingerprint(sdp: &str) -> Result<Vec<u8>, Error> {
    let mut lines = sdp
        .lines()
        .filter_map(|l| l.trim().strip_prefix("a=fingerprint:"));
    let first = lines.next().ok_or("missing DTLS fingerprint")?;
    if lines.any(|line| !line.eq_ignore_ascii_case(first)) {
        return Err("conflicting fingerprints".into());
    }
    let (algo, hex) = first.split_once(' ').ok_or("invalid fingerprint")?;
    let bytes = hex
        .split(':')
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<Vec<_>, _>>()?;
    if !algo.eq_ignore_ascii_case("sha-256") || bytes.len() != 32 {
        return Err("expected SHA-256 certificate".into());
    }
    Ok(bytes)
}

pub async fn answer(
    offer: &str,
    client: &ServerClient,
    host: Arc<Mutex<Host>>,
    bridge: AgentBridge,
    stop: watch::Receiver<bool>,
    slot: OwnedSemaphorePermit,
) -> Result<String, Error> {
    answer_with_ice(offer, client.ice_servers().await?, host, bridge, stop, slot).await
}

async fn answer_with_ice(
    offer: &str,
    ice_servers: Vec<RTCIceServer>,
    host: Arc<Mutex<Host>>,
    bridge: AgentBridge,
    mut stop: watch::Receiver<bool>,
    slot: OwnedSemaphorePermit,
) -> Result<String, Error> {
    let viewer_fp = fingerprint(offer)?;
    let mut media = MediaEngine::default();
    media.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media)?;
    let api = APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .build();
    let pc = api
        .new_peer_connection(RTCConfiguration {
            ice_servers,
            ..Default::default()
        })
        .await?;
    let track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: "video/H264".into(),
            clock_rate: 90_000,
            sdp_fmtp_line: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
                .into(),
            ..Default::default()
        },
        "screen".into(),
        "desktop".into(),
    ));
    let (events, mut opened) = mpsc::channel(1);
    pc.on_data_channel(Box::new(move |dc| {
        let events = events.clone();
        Box::pin(async move {
            if dc.label() != "moonrd" {
                let _ = dc.close().await;
                return;
            }
            let (tx, rx) = mpsc::channel(128);
            let (closed, ended) = watch::channel(false);
            dc.on_close(Box::new(move || {
                let _ = closed.send(true);
                Box::pin(async {})
            }));
            dc.on_message(Box::new(move |m| {
                let tx = tx.clone();
                Box::pin(async move {
                    if m.data.len() <= 8192 {
                        let _ = tx.send(m.data).await;
                    }
                })
            }));
            let active = dc.clone();
            dc.on_open(Box::new(move || {
                Box::pin(async move {
                    let _ = events.send((active, rx, ended)).await;
                })
            }));
        })
    }));
    let setup = async {
        let sender = pc.add_track(track.clone()).await?;
        pc.set_remote_description(RTCSessionDescription::offer(offer.into())?)
            .await?;
        let answer = pc.create_answer(None).await?;
        let mut gathered = pc.gathering_complete_promise().await;
        pc.set_local_description(answer).await?;
        let _ = tokio::time::timeout(Duration::from_secs(5), gathered.recv()).await;
        let local = pc.local_description().await.ok_or("missing SDP answer")?;
        let binding = ChannelBinding::from_dtls_fingerprints(&viewer_fp, &fingerprint(&local.sdp)?);
        Ok::<_, Error>((local.sdp, binding, sender))
    }
    .await;
    let (sdp, binding, sender) = match setup {
        Ok(s) => s,
        Err(e) => {
            let _ = pc.close().await;
            return Err(e);
        }
    };
    tokio::spawn(async move {
        let _slot = slot;
        let work = async {
            let Some((dc, rx, mut ended)) = opened.recv().await else {
                return;
            };
            drop(opened);
            tokio::select! {
                _ = ended.changed() => {},
                _ = session(dc, rx, binding, host, bridge, track, sender) => {},
            }
        };
        let mut state = pc.connection_state();
        let (state_tx, mut state_rx) = watch::channel(state);
        pc.on_peer_connection_state_change(Box::new(move |s| {
            let _ = state_tx.send(s);
            Box::pin(async {})
        }));
        let disconnected = async {
            use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::*;
            let deadline = tokio::time::sleep(Duration::from_secs(45));
            tokio::pin!(deadline);
            let mut connected = false;
            loop {
                match state {
                    Failed | Closed | Disconnected => break,
                    Connected => connected = true,
                    _ => {}
                }
                tokio::select! {
                    _ = &mut deadline, if !connected => break,
                    res = state_rx.changed() => { if res.is_err() { break; } state = *state_rx.borrow_and_update(); }
                }
            }
        };
        tokio::select! { _ = stop.changed() => {}, _ = disconnected => {}, _ = work => {} }
        let _ = pc.close().await;
    });
    Ok(sdp)
}

#[cfg(test)]
#[path = "web_qa.rs"]
mod qa;

async fn session(
    dc: Arc<RTCDataChannel>,
    mut rx: mpsc::Receiver<bytes::Bytes>,
    binding: ChannelBinding,
    host: Arc<Mutex<Host>>,
    bridge: AgentBridge,
    track: Arc<TrackLocalStaticSample>,
    sender: Arc<RTCRtpSender>,
) -> Result<(), Error> {
    let ctx = {
        let h = host.lock().unwrap_or_else(|e| e.into_inner());
        let reg = h.state.registration.as_ref().ok_or("unregistered")?;
        HostContext {
            host_device_id: reg.device_id.clone(),
            host_display_name: reg.name.clone(),
            host_version: env!("CARGO_PKG_VERSION").into(),
            binding,
            transport_viewer_device: Some(String::new()),
            pin: h.state.pin.clone(),
            support_code: None,
            policy: Policy::default(),
        }
    };
    let mut handshake = HostHandshake::new(ctx);
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let msg = decode(&rx.recv().await.ok_or("closed")?)?;
            let result =
                handshake.on_message(msg, &mut *host.lock().unwrap_or_else(|e| e.into_inner()));
            let (messages, done, failed) = match result {
                Outcome::Continue(out) => (out, false, false),
                Outcome::Established { out, .. } => (out, true, false),
                Outcome::Failed { out, .. } => (out, false, true),
                _ => return Err("unsupported authentication".into()),
            };
            for msg in messages {
                dc.send(&frame::encode(&msg).into()).await?;
            }
            if done {
                return Ok::<(), Error>(());
            }
            if failed {
                return Err("authentication rejected".into());
            }
        }
    })
    .await??;
    let ViewerAttachment { input, mut from_agent } = bridge.attach_viewer();
    let read_input = async {
        while let Some(msg) = rx.recv().await {
            let env = decode(&msg)?;
            match env.msg {
                Some(Msg::Pointer(_) | Msg::Key(_)) => { input.send_to_agent(env); }
                Some(Msg::Bye(_)) => break,
                _ => {}
            }
        }
        Ok(())
    };
    let send_output = async {
        let mut last_time = None;
        while let Some(env) = from_agent.recv().await {
            match env.msg {
                Some(Msg::VideoFrame(f)) => {
                    let interval = last_time.map_or(33_333, |t| f.capture_time_us.saturating_sub(t).clamp(1000,1_000_000));
                    last_time = Some(f.capture_time_us);
                    track.write_sample(&Sample { data: f.data.into(), duration: Duration::from_micros(interval), ..Default::default() }).await?;
                }
                Some(Msg::DisplayList(_) | Msg::VideoConfig(_) | Msg::Notice(_)) => { dc.send(&frame::encode(&env).into()).await?; }
                _ => {}
            }
        }
        Ok(())
    };
    tokio::select! {
        result = read_input => result,
        result = send_output => result,
        result = forward_keyframe_feedback(&sender, &input) => result,
    }
}

async fn forward_keyframe_feedback(sender: &RTCRtpSender, input: &ViewerInput) -> Result<(), Error> {
    let mut next_request = Instant::now();
    loop {
        let (packets, _) = sender.read_rtcp().await?;
        let now = Instant::now();
        if now >= next_request && packets.iter().any(|packet| {
            packet.as_any().is::<PictureLossIndication>() || packet.as_any().is::<FullIntraRequest>()
        }) && input.send_to_agent(Envelope { msg: Some(Msg::KeyframeRequest(KeyframeRequest::default())) }) {
            next_request = now + Duration::from_millis(250);
        }
    }
}

fn decode(data: &[u8]) -> Result<Envelope, Error> {
    let mut d = frame::Decoder::new();
    d.push(data);
    let msg = d.next_frame()?.ok_or("incomplete control frame")?;
    if d.pending() != 0 {
        return Err("unexpected trailing data".into());
    }
    Ok(msg)
}
