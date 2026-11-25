//! End-to-end over loopback QUIC: raw-public-key handshake, channel binding, control
//! stream and a full PIN authentication on top.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use moonrd_proto::{auth_message::Step, envelope::Msg, AuthMessage, AuthMethod, Envelope};
use moonrd_session::pake::{Pake, Role};
use moonrd_session::pin::{PinVerifier, Secret};
use moonrd_transport::{accept, connect, host_endpoint, viewer_endpoint, AllowList, ControlStream, DeviceKey, Error};
use rand_core::OsRng;

fn device() -> DeviceKey {
    let sk = SigningKey::generate(&mut OsRng);
    DeviceKey::new(sk.to_bytes(), sk.verifying_key().to_bytes())
}

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

fn auth(step: Step) -> Envelope {
    Envelope { msg: Some(Msg::Auth(AuthMessage { step: Some(step) })) }
}

async fn recv_step(c: &mut ControlStream) -> Step {
    match c.recv().await.unwrap().and_then(|e| e.msg) {
        Some(Msg::Auth(AuthMessage { step: Some(s) })) => s,
        other => panic!("expected auth message, got {other:?}"),
    }
}

/// Runs SPAKE2 over the control stream; returns whether this side accepted the peer.
async fn run_pake(c: &mut ControlStream, role: Role, secret: &Secret, binding: &moonrd_session::pake::ChannelBinding) -> bool {
    let (pake, msg) = Pake::start(role, AuthMethod::Pin, secret, binding);
    c.send(&auth(Step::Spake2Message(msg))).await.unwrap();
    let Step::Spake2Message(peer) = recv_step(c).await else { panic!("expected spake2 message") };
    let keys = pake.finish(&peer).unwrap();
    c.send(&auth(Step::KeyConfirmation(keys.confirmation().to_vec()))).await.unwrap();
    let Step::KeyConfirmation(tag) = recv_step(c).await else { panic!("expected confirmation") };
    keys.verify_peer(&tag).is_ok()
}

#[tokio::test]
async fn pin_session_over_quic() {
    let host_key = device();
    let viewer_key = device();
    let host_ep = host_endpoint(loopback(), &host_key, AllowList::new([*viewer_key.public()])).unwrap();
    let host_addr = host_ep.local_addr().unwrap();
    let verifier = PinVerifier::create("482916").unwrap();
    let (salt, params) = (verifier.salt, verifier.params);
    let viewer_pub = *viewer_key.public();

    let host = tokio::spawn(async move {
        let s = accept(&host_ep).await.unwrap().unwrap();
        assert_eq!(s.peer_key, viewer_pub, "host must see the viewer's device key");
        let mut c = s.accept_control().await.unwrap();
        let ok = run_pake(&mut c, Role::Host, &verifier.secret(), &s.binding).await;
        (ok, s.binding)
    });

    let viewer_ep = viewer_endpoint(loopback()).unwrap();
    let s = connect(&viewer_ep, host_addr, &viewer_key, *host_key.public()).await.unwrap();
    assert_eq!(s.peer_key, *host_key.public());
    let mut c = s.open_control().await.unwrap();
    let secret = Secret::derive("482916", &salt, params).unwrap();
    let viewer_ok = run_pake(&mut c, Role::Viewer, &secret, &s.binding).await;

    let (host_ok, host_binding) = host.await.unwrap();
    assert!(viewer_ok && host_ok);
    assert_eq!(host_binding, s.binding, "both ends must derive the same exporter binding");
}

#[tokio::test]
async fn wrong_pin_is_rejected_over_quic() {
    let host_key = device();
    let viewer_key = device();
    let host_ep = host_endpoint(loopback(), &host_key, AllowList::new([*viewer_key.public()])).unwrap();
    let host_addr = host_ep.local_addr().unwrap();
    let verifier = PinVerifier::create("482916").unwrap();
    let (salt, params) = (verifier.salt, verifier.params);

    let host = tokio::spawn(async move {
        let s = accept(&host_ep).await.unwrap().unwrap();
        let mut c = s.accept_control().await.unwrap();
        run_pake(&mut c, Role::Host, &verifier.secret(), &s.binding).await
    });
    let viewer_ep = viewer_endpoint(loopback()).unwrap();
    let s = connect(&viewer_ep, host_addr, &viewer_key, *host_key.public()).await.unwrap();
    let mut c = s.open_control().await.unwrap();
    let wrong = Secret::derive("111222", &salt, params).unwrap();
    assert!(!run_pake(&mut c, Role::Viewer, &wrong, &s.binding).await);
    assert!(!host.await.unwrap());
}

#[tokio::test]
async fn viewer_rejects_unexpected_host_key() {
    let host_key = device();
    let impostor = device();
    let viewer_key = device();
    let host_ep = host_endpoint(loopback(), &host_key, AllowList::new([*viewer_key.public()])).unwrap();
    let host_addr = host_ep.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = accept(&host_ep).await;
    });
    let viewer_ep = viewer_endpoint(loopback()).unwrap();
    let err = connect(&viewer_ep, host_addr, &viewer_key, *impostor.public()).await.err().expect("must fail");
    assert!(matches!(err, Error::Connection(_)), "{err}");
}

#[tokio::test]
async fn host_rejects_viewer_not_on_allow_list_and_picks_up_changes() {
    let host_key = device();
    let viewer_key = device();
    let allow = AllowList::default();
    let host_ep = host_endpoint(loopback(), &host_key, allow.clone()).unwrap();
    let host_addr = host_ep.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(r) = accept(&host_ep).await {
            let ok = r.is_ok();
            if let Ok(s) = r {
                // Keep the connection alive long enough for the viewer to use it.
                let _ = s.accept_control().await;
            }
            let _ = tx.send(ok);
        }
    });

    let viewer_ep = viewer_endpoint(loopback()).unwrap();
    // Not allowed: the host aborts the handshake. In TLS 1.3 the client may finish its
    // side first, so the failure can surface at connect or at first use.
    let refused = async {
        let s = connect(&viewer_ep, host_addr, &viewer_key, *host_key.public()).await?;
        let mut c = s.open_control().await?;
        c.send(&Envelope::default()).await?;
        c.recv().await
    };
    assert!(tokio::time::timeout(Duration::from_secs(10), refused).await.unwrap().is_err());
    assert_eq!(rx.recv().await, Some(false));

    // Device added to the account: the next handshake succeeds without restarting.
    allow.replace([*viewer_key.public()]);
    let s = connect(&viewer_ep, host_addr, &viewer_key, *host_key.public()).await.unwrap();
    let mut c = s.open_control().await.unwrap();
    c.send(&Envelope::default()).await.unwrap();
    assert_eq!(rx.recv().await, Some(true));
}

#[test]
fn device_key_must_match_its_seed() {
    let a = SigningKey::generate(&mut OsRng);
    let b = SigningKey::generate(&mut OsRng);
    let mismatched = DeviceKey::new(a.to_bytes(), b.verifying_key().to_bytes());
    assert!(host_endpoint(loopback(), &mismatched, AllowList::default()).is_err());
}

mod full_handshake {
    use super::*;
    use moonrd_proto::SessionKind;
    use moonrd_session::handshake::{HostContext, HostHandshake, HostStore, Outcome, ViewerContext, ViewerHandshake};
    use moonrd_session::lockout::{Lockout, Policy};
    use moonrd_session::pairing::Pairings;

    #[derive(Default)]
    struct Store {
        lockout: Lockout,
        pairings: Pairings,
    }

    impl HostStore for Store {
        fn now(&self) -> u64 {
            1_000
        }
        fn lockout(&mut self) -> &mut Lockout {
            &mut self.lockout
        }
        fn pairings(&mut self) -> &mut Pairings {
            &mut self.pairings
        }
        fn persist(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    /// Host loop: feed every received message to the handshake until it ends.
    async fn host_side(c: &mut ControlStream, mut hs: HostHandshake) -> Option<[u8; 32]> {
        let mut store = Store::default();
        loop {
            let msg = c.recv().await.ok()??;
            match hs.on_message(msg, &mut store) {
                Outcome::Continue(out) => {
                    for m in out {
                        c.send(&m).await.ok()?;
                    }
                }
                Outcome::Established { out, session } => {
                    for m in out {
                        c.send(&m).await.ok()?;
                    }
                    return Some(session.session_key);
                }
                Outcome::Failed { out, .. } => {
                    for m in out {
                        let _ = c.send(&m).await;
                    }
                    c.finish_and_flush(Duration::from_secs(2)).await;
                    return None;
                }
                other => panic!("host: {other:?}"),
            }
        }
    }

    async fn viewer_side(c: &mut ControlStream, mut hs: ViewerHandshake, hello: Envelope, pin: &str) -> Option<[u8; 32]> {
        c.send(&hello).await.ok()?;
        loop {
            let msg = c.recv().await.ok()??;
            let mut o = hs.on_message(msg);
            if let Outcome::NeedSecret { out, .. } = o {
                for m in out {
                    c.send(&m).await.ok()?;
                }
                o = hs.provide_secret(pin);
            }
            match o {
                Outcome::Continue(out) => {
                    for m in out {
                        c.send(&m).await.ok()?;
                    }
                }
                Outcome::Established { session, .. } => return Some(session.session_key),
                Outcome::Failed { failure, .. } => panic!("viewer failed: {failure:?}"),
                other => panic!("viewer: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn refusal_reaches_viewer_before_close() {
        let host_key = device();
        let viewer_key = device();
        let host_ep = host_endpoint(loopback(), &host_key, AllowList::new([*viewer_key.public()])).unwrap();
        let host_addr = host_ep.local_addr().unwrap();
        tokio::spawn(async move {
            let s = accept(&host_ep).await.unwrap().unwrap();
            let mut c = s.accept_control().await.unwrap();
            let ctx = HostContext {
                host_device_id: "host-1".into(),
                host_display_name: "Office PC".into(),
                host_version: "test".into(),
                binding: s.binding,
                transport_viewer_device: Some("viewer-1".into()),
                pin: None, // no PIN set: remote access is refused
                support_code: None,
                policy: Policy::default(),
            };
            host_side(&mut c, HostHandshake::new(ctx)).await;
            // Connection dropped right after the flush, as the service would.
        });
        let viewer_ep = viewer_endpoint(loopback()).unwrap();
        let s = connect(&viewer_ep, host_addr, &viewer_key, *host_key.public()).await.unwrap();
        let mut c = s.open_control().await.unwrap();
        let (mut hs, hello) = ViewerHandshake::new(ViewerContext {
            kind: SessionKind::RemoteAccess,
            device_id: "viewer-1".into(),
            display_name: "Alice".into(),
            client_version: "test".into(),
            binding: s.binding,
            pairing: None,
        });
        c.send(&hello).await.unwrap();
        let mut failure = None;
        while let Ok(Some(m)) = c.recv().await {
            if let Outcome::Failed { failure: f, .. } = hs.on_message(m) {
                failure = Some(f);
                break;
            }
        }
        assert_eq!(failure, Some(moonrd_session::handshake::Failure::NotAllowed));
    }

    #[tokio::test]
    async fn state_machines_over_quic() {
        let host_key = device();
        let viewer_key = device();
        let host_ep = host_endpoint(loopback(), &host_key, AllowList::new([*viewer_key.public()])).unwrap();
        let host_addr = host_ep.local_addr().unwrap();
        let verifier = PinVerifier::create("482916").unwrap();

        let host = tokio::spawn(async move {
            let s = accept(&host_ep).await.unwrap().unwrap();
            let mut c = s.accept_control().await.unwrap();
            let ctx = HostContext {
                host_device_id: "host-1".into(),
                host_display_name: "Office PC".into(),
                host_version: "test".into(),
                binding: s.binding,
                // In the service this comes from mapping s.peer_key through the device list.
                transport_viewer_device: Some("viewer-1".into()),
                pin: Some(verifier),
                support_code: None,
                policy: Policy::default(),
            };
            let key = host_side(&mut c, HostHandshake::new(ctx)).await;
            // A real host keeps the connection for the session; dropping it here could
            // discard the AuthResult before the viewer reads it.
            (key, s, c)
        });

        let viewer_ep = viewer_endpoint(loopback()).unwrap();
        let s = connect(&viewer_ep, host_addr, &viewer_key, *host_key.public()).await.unwrap();
        let mut c = s.open_control().await.unwrap();
        let (hs, hello) = ViewerHandshake::new(ViewerContext {
            kind: SessionKind::RemoteAccess,
            device_id: "viewer-1".into(),
            display_name: "Alice".into(),
            client_version: "test".into(),
            binding: s.binding,
            pairing: None,
        });
        let viewer_key_out = viewer_side(&mut c, hs, hello, "482916").await;
        let (host_key_out, _s, _c) = host.await.unwrap();
        assert!(viewer_key_out.is_some());
        assert_eq!(viewer_key_out, host_key_out, "both ends hold the same session key");
    }
}
