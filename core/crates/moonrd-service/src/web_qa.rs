//! Opt-in host/viewer fixtures for exercising real QUIC and WebRTC over an impaired link.
use super::*;
use crate::{
    agent_pipe::serve_stream,
    quic_host,
    server_api::DeviceView,
    state::{Protector, Registration, StateFile},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::SigningKey;
use moonrd_proto::{KeyEvent, PointerEvent, VideoFrame};
use moonrd_session::handshake::ViewerContext;
use moonrd_transport::DeviceKey;
use std::{
    io::{self, BufRead},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PIN: &str = "581739";
const VIEWER_ID: &str = "qa-viewer";

struct Plain;
impl Protector for Plain {
    fn protect(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    fn unprotect(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

fn viewer_key() -> DeviceKey {
    // A disposable fixture identity scoped to this loopback-only test host.
    let seed = [42; 32];
    let sk = SigningKey::from_bytes(&seed);
    DeviceKey::new(seed, sk.verifying_key().to_bytes())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through the dual-machine QA harness"]
async fn qa_host() -> Result<(), Error> {
    let fixture = std::env::var("MRD_QA_H264").ok().map(|path| {
        let text = std::fs::read_to_string(path).unwrap();
        serde_json::from_str::<Vec<String>>(&text)
            .unwrap()
            .into_iter()
            .map(|line| B64.decode(line).unwrap())
            .collect::<Vec<_>>()
    });
    let directory = tempfile::tempdir()?;
    let mut host = Host::open(StateFile::new(
        directory.path().join("state"),
        Box::new(Plain),
    ))?;
    host.complete_registration(Registration {
        server_url: "http://127.0.0.1".into(),
        device_id: "qa-host".into(),
        user_sub: "qa".into(),
        name: "QA fixture".into(),
        device_token: "qa".into(),
        roster_key: "AAAA".into(),
        roster_key_id: "qa".into(),
    })?;
    host.set_pin(PIN)?;
    let key = host.device_key()?;
    let host_key = DeviceKey::new(key.to_bytes(), key.verifying_key().to_bytes());
    let host = Arc::new(Mutex::new(host));
    let roster = quic_host::DeviceDirectory::new();
    roster.update(
        &[DeviceView {
            id: VIEWER_ID.into(),
            name: "QA viewer".into(),
            kind: "viewer".into(),
            public_key: B64.encode(viewer_key().public()),
            online: true,
            is_self: false,
        }],
        &host,
    );

    let bridge = AgentBridge::new();
    let (stop, stopping) = watch::channel(false);
    let (endpoint, port) = quic_host::bind_loopback(&host_key, &roster)?;
    tokio::spawn(quic_host::serve(
        endpoint,
        host.clone(),
        roster,
        bridge.clone(),
        Arc::new(|| Ok(())),
        stopping.clone(),
        |_| {},
    ));
    let (service, agent) = tokio::io::duplex(64 * 1024);
    tokio::spawn(serve_stream(service, bridge.clone(), stopping.clone()));
    let (mut agent_in, mut agent_out) = tokio::io::split(agent);
    let requests = Arc::new(AtomicU64::new(0));
    let input_requests = requests.clone();
    tokio::spawn(async move {
        let mut decoder = frame::Decoder::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = agent_in.read(&mut buf).await {
            if n == 0 {
                break;
            }
            decoder.push(&buf[..n]);
            while let Ok(Some(message)) = decoder.next_frame() {
                match message.msg {
                    Some(Msg::KeyframeRequest(_)) => {
                        println!(
                            "QA_REQUEST {}",
                            input_requests.fetch_add(1, Ordering::Relaxed) + 1
                        );
                    }
                    Some(Msg::Key(k)) if k.pressed => println!("QA_KEY {}", k.scancode),
                    Some(Msg::Pointer(p)) if p.pressed => println!("QA_CLICK {}", p.x),
                    _ => {}
                }
            }
        }
    });
    tokio::spawn(async move {
        let mut sequence = 0;
        let mut last_request = 0;
        let mut index = 0;
        let mut cadence = tokio::time::interval(Duration::from_millis(33));
        cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let bulk = vec![0; 512 * 1024];
        loop {
            cadence.tick().await;
            let request = requests.load(Ordering::Relaxed);
            if request == 0 {
                continue;
            }
            let keyframe = request != last_request;
            if keyframe {
                index = 0;
            }
            last_request = request;
            let data = match &fixture {
                Some(frames) => {
                    let data = frames[index].clone();
                    index = if index + 1 == frames.len() {
                        1
                    } else {
                        index + 1
                    };
                    data
                }
                None => bulk.clone(),
            };
            sequence += 1;
            let frame = Envelope {
                msg: Some(Msg::VideoFrame(VideoFrame {
                    sequence,
                    capture_time_us: sequence * 33_333,
                    keyframe,
                    data,
                })),
            };
            if agent_out
                .write_all(&moonrd_session::frame::encode(&frame))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    println!("QA_READY {port} {}", B64.encode(host_key.public()));
    let (commands, mut input) = mpsc::channel(4);
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines().map_while(Result::ok) {
            if commands.blocking_send(line).is_err() {
                break;
            }
        }
    });
    while let Some(line) = input.recv().await {
        if line == "quit" {
            break;
        }
        let offer = String::from_utf8(B64.decode(line)?)?;
        let slot = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await?;
        let answer = answer_with_ice(
            &offer,
            vec![],
            host.clone(),
            bridge.clone(),
            stopping.clone(),
            slot,
        )
        .await?;
        println!("QA_ANSWER {}", B64.encode(answer));
    }
    let _ = stop.send(true);
    Ok(())
}

#[tokio::test]
#[ignore = "run through the dual-machine QA harness"]
async fn qa_quic_viewer() {
    let addr = std::env::var("MRD_QA_ADDRESS").unwrap().parse().unwrap();
    let host = B64
        .decode(std::env::var("MRD_QA_KEY").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let endpoint = moonrd_transport::viewer_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    let session = moonrd_transport::connect(&endpoint, addr, &viewer_key(), host)
        .await
        .unwrap();
    let mut control = session.open_control().await.unwrap();
    quic_host::tests::run_viewer_handshake(
        &mut control,
        ViewerContext {
            kind: moonrd_proto::SessionKind::RemoteAccess,
            device_id: VIEWER_ID.into(),
            display_name: "QA viewer".into(),
            client_version: "qa".into(),
            binding: session.binding,
            pairing: None,
        },
        Some(PIN),
    )
    .await
    .unwrap();
    println!("QA_CONNECTED");
    // Stop reading media until the host is blocked by the receive window.
    tokio::time::sleep(Duration::from_secs(4)).await;
    for sequence in 4..14 {
        println!("QA_SENT {sequence}");
        control
            .send(&Envelope {
                msg: Some(Msg::Key(KeyEvent {
                    scancode: sequence,
                    pressed: true,
                    ..Default::default()
                })),
            })
            .await
            .unwrap();
        control
            .send(&Envelope {
                msg: Some(Msg::Pointer(PointerEvent {
                    x: sequence,
                    y: sequence,
                    button: 1,
                    pressed: true,
                    ..Default::default()
                })),
            })
            .await
            .unwrap();
        control
            .send(&Envelope {
                msg: Some(Msg::Key(KeyEvent {
                    scancode: sequence,
                    pressed: false,
                    ..Default::default()
                })),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(220)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
}
