//! Handshake scenarios: both state machines wired together in memory.

use std::collections::VecDeque;

use moonrd_session::handshake::{
    grant_pairing, Failure, HeldPairing, HostContext, HostHandshake, HostStore, Outcome, ViewerContext, ViewerHandshake, ViewerInfo,
};
use moonrd_session::lockout::{Lockout, Policy};
use moonrd_session::pairing::Pairings;
use moonrd_session::pake::ChannelBinding;
use moonrd_session::pin::PinVerifier;
use moonrd_session::proto::{auth_message::Step, envelope::Msg, AuthMessage, AuthMethod, AuthResult, AuthStatus, Envelope, SessionKind};

#[derive(Default)]
struct Store {
    now: u64,
    lockout: Lockout,
    pairings: Pairings,
    fail_persist: bool,
    persists: u32,
}

impl HostStore for Store {
    fn now(&self) -> u64 {
        self.now
    }
    fn lockout(&mut self) -> &mut Lockout {
        &mut self.lockout
    }
    fn pairings(&mut self) -> &mut Pairings {
        &mut self.pairings
    }
    fn persist(&mut self) -> Result<(), String> {
        if self.fail_persist {
            return Err("disk full".into());
        }
        self.persists += 1;
        Ok(())
    }
}

const PIN: &str = "482916";

fn binding() -> ChannelBinding {
    ChannelBinding::from_bytes([5; 32])
}

fn host_ctx(pin: Option<PinVerifier>) -> HostContext {
    HostContext {
        host_device_id: "host-1".into(),
        host_display_name: "Office PC".into(),
        host_version: "0.1.0".into(),
        binding: binding(),
        transport_viewer_device: Some("viewer-1".into()),
        pin,
        support_code: None,
        policy: Policy::default(),
    }
}

fn viewer_ctx(pairing: Option<HeldPairing>) -> ViewerContext {
    ViewerContext {
        kind: SessionKind::RemoteAccess,
        device_id: "viewer-1".into(),
        display_name: "Alice".into(),
        client_version: "0.1.0".into(),
        binding: binding(),
        pairing,
    }
}

#[derive(Debug, PartialEq)]
enum End {
    Ok { method: AuthMethod, key: [u8; 32] },
    Fail(Failure),
}

/// What the "user" does when the machines ask.
struct Script<'a> {
    secret: &'a str,
    consent: bool,
}

/// Pumps messages until both sides finished. Returns (host end, viewer end, viewer info
/// the host saw).
fn drive(host: &mut HostHandshake, viewer: &mut ViewerHandshake, hello: Envelope, store: &mut Store, script: Script) -> (Option<End>, Option<End>) {
    let mut to_host: VecDeque<Envelope> = VecDeque::from([hello]);
    let mut to_viewer: VecDeque<Envelope> = VecDeque::new();
    let (mut host_end, mut viewer_end) = (None, None);

    loop {
        if let Some(m) = to_host.pop_front() {
            if host_end.is_some() {
                continue; // host closed; drop
            }
            let mut o = host.on_message(m, store);
            if let Outcome::NeedConsent { .. } = o {
                o = host.consent(script.consent);
            }
            match o {
                Outcome::Continue(out) => to_viewer.extend(out),
                Outcome::Established { out, session } => {
                    to_viewer.extend(out);
                    host_end = Some(End::Ok { method: session.method, key: session.session_key });
                }
                Outcome::Failed { out, failure } => {
                    to_viewer.extend(out);
                    host_end = Some(End::Fail(failure));
                }
                other => panic!("host: {other:?}"),
            }
            continue;
        }
        if let Some(m) = to_viewer.pop_front() {
            if viewer_end.is_some() {
                continue;
            }
            let mut o = viewer.on_message(m);
            if let Outcome::NeedSecret { out, .. } = o {
                to_host.extend(out);
                o = viewer.provide_secret(script.secret);
            }
            match o {
                Outcome::Continue(out) => to_host.extend(out),
                Outcome::Established { out, session } => {
                    to_host.extend(out);
                    viewer_end = Some(End::Ok { method: session.method, key: session.session_key });
                }
                Outcome::Failed { out, failure } => {
                    to_host.extend(out);
                    viewer_end = Some(End::Fail(failure));
                }
                other => panic!("viewer: {other:?}"),
            }
            continue;
        }
        return (host_end, viewer_end);
    }
}

fn attempt(store: &mut Store, verifier: &PinVerifier, pin: &str, pairing: Option<HeldPairing>) -> (Option<End>, Option<End>) {
    let mut host = HostHandshake::new(host_ctx(Some(verifier.clone())));
    let (mut viewer, hello) = ViewerHandshake::new(viewer_ctx(pairing));
    drive(&mut host, &mut viewer, hello, store, Script { secret: pin, consent: false })
}

#[test]
fn pin_login() {
    let v = PinVerifier::create(PIN).unwrap();
    let mut store = Store::default();
    let (h, w) = attempt(&mut store, &v, PIN, None);
    match (h, w) {
        (Some(End::Ok { method: AuthMethod::Pin, key: hk }), Some(End::Ok { method: AuthMethod::Pin, key: vk })) => assert_eq!(hk, vk),
        other => panic!("{other:?}"),
    }
    assert_eq!(store.lockout, Lockout::default(), "success clears the counter");
    assert!(store.persists >= 2, "attempt persisted before the PAKE and again after success");
}

#[test]
fn wrong_pins_then_lockout() {
    let v = PinVerifier::create(PIN).unwrap();
    let mut store = Store { now: 1_000, ..Default::default() };
    for expected_remaining in [4, 3, 2, 1] {
        let (h, w) = attempt(&mut store, &v, "111222", None);
        let want = Failure::BadSecret { method: AuthMethod::Pin, remaining: expected_remaining, lockout_secs: 0 };
        assert_eq!(h, Some(End::Fail(want.clone())));
        assert_eq!(w, Some(End::Fail(want)));
    }
    // Fifth failure arms the lockout and the viewer is told how long.
    let (_, w) = attempt(&mut store, &v, "111222", None);
    assert_eq!(w, Some(End::Fail(Failure::BadSecret { method: AuthMethod::Pin, remaining: 0, lockout_secs: 30 })));
    // Even the right PIN is refused now, without running the PAKE.
    let (h, w) = attempt(&mut store, &v, PIN, None);
    assert_eq!(h, Some(End::Fail(Failure::LockedOut { retry_after: 30 })));
    assert_eq!(w, Some(End::Fail(Failure::LockedOut { retry_after: 30 })));
    store.now += 30;
    let (h, _) = attempt(&mut store, &v, PIN, None);
    assert!(matches!(h, Some(End::Ok { .. })));
}

#[test]
fn storage_failure_refuses_before_pake() {
    let v = PinVerifier::create(PIN).unwrap();
    let mut store = Store { fail_persist: true, ..Default::default() };
    let (h, w) = attempt(&mut store, &v, PIN, None);
    assert_eq!(h, Some(End::Fail(Failure::Storage("disk full".into()))));
    assert!(matches!(w, Some(End::Fail(Failure::Protocol(_)))), "viewer sees the host close: {w:?}");
}

#[test]
fn pairing_after_pin_then_pairing_login() {
    let v = PinVerifier::create(PIN).unwrap();
    let mut store = Store::default();
    let (h, _) = attempt(&mut store, &v, PIN, None);
    assert!(matches!(h, Some(End::Ok { method: AuthMethod::Pin, .. })));

    let viewer = ViewerInfo { kind: SessionKind::RemoteAccess, device_id: "viewer-1".into(), display_name: "Alice".into(), client_version: "0.1.0".into() };
    let Some(Msg::Auth(AuthMessage { step: Some(Step::PairingGrant(g)) })) = grant_pairing(AuthMethod::Pin, &viewer, "Alice's laptop", &mut store).msg else {
        panic!("no grant")
    };
    assert_eq!(g.pairing_id.len(), 16);
    let held = HeldPairing { id: g.pairing_id.clone(), key: g.pairing_key.as_slice().try_into().unwrap() };

    // Next login uses the pairing; the user is never asked (script secret is wrong on purpose).
    let (h, w) = attempt(&mut store, &v, "000001", Some(held.clone()));
    assert!(matches!(h, Some(End::Ok { method: AuthMethod::Pairing, .. })), "{h:?}");
    assert!(matches!(w, Some(End::Ok { method: AuthMethod::Pairing, .. })), "{w:?}");

    // Pairing is not granted after a pairing login, nor to a device-less (web) viewer.
    let declined = grant_pairing(AuthMethod::Pairing, &viewer, "x", &mut store);
    let web = ViewerInfo { device_id: String::new(), ..viewer };
    let declined_web = grant_pairing(AuthMethod::Pin, &web, "x", &mut store);
    for d in [declined, declined_web] {
        let Some(Msg::Auth(AuthMessage { step: Some(Step::PairingGrant(g)) })) = d.msg else { panic!() };
        assert!(g.pairing_id.is_empty() && g.pairing_key.is_empty());
    }

    // Revoked pairing: the host falls back to the PIN.
    store.pairings.revoke(&held.id);
    let (h, _) = attempt(&mut store, &v, PIN, Some(held));
    assert!(matches!(h, Some(End::Ok { method: AuthMethod::Pin, .. })), "{h:?}");
}

#[test]
fn stolen_pairing_id_from_other_device_falls_back_to_pin() {
    let v = PinVerifier::create(PIN).unwrap();
    let mut store = Store::default();
    let p = store.pairings.grant("viewer-2", "other", 0);
    let held = HeldPairing { id: p.id.to_vec(), key: p.key };
    // viewer-1 presents viewer-2's pairing (even with the right key): not accepted.
    let (h, _) = attempt(&mut store, &v, PIN, Some(held));
    assert!(matches!(h, Some(End::Ok { method: AuthMethod::Pin, .. })), "{h:?}");
}

#[test]
fn transport_identity_must_match_hello() {
    let v = PinVerifier::create(PIN).unwrap();
    let mut store = Store::default();
    let mut host = HostHandshake::new(host_ctx(Some(v)));
    let (mut viewer, hello) = ViewerHandshake::new(ViewerContext { device_id: "viewer-9".into(), ..viewer_ctx(None) });
    let (h, w) = drive(&mut host, &mut viewer, hello, &mut store, Script { secret: PIN, consent: false });
    assert_eq!(h, Some(End::Fail(Failure::NotAllowed)));
    assert_eq!(w, Some(End::Fail(Failure::NotAllowed)));
    assert_eq!(store.lockout, Lockout::default(), "refusal must not consume a PIN attempt");
}

#[test]
fn no_pin_set_refuses_remote_access() {
    let mut store = Store::default();
    let mut host = HostHandshake::new(host_ctx(None));
    let (mut viewer, hello) = ViewerHandshake::new(viewer_ctx(None));
    let (h, w) = drive(&mut host, &mut viewer, hello, &mut store, Script { secret: PIN, consent: false });
    assert_eq!((h, w), (Some(End::Fail(Failure::NotAllowed)), Some(End::Fail(Failure::NotAllowed))));
}

fn support(code: &str, entered: &str, consent: bool) -> (Option<End>, Option<End>) {
    let mut store = Store::default();
    let ctx = HostContext {
        transport_viewer_device: None, // WebRTC: the helper is any account, unauthenticated at transport level
        pin: None,
        support_code: Some(PinVerifier::for_support_code(code).unwrap()),
        ..host_ctx(None)
    };
    let mut host = HostHandshake::new(ctx);
    let (mut viewer, hello) =
        ViewerHandshake::new(ViewerContext { kind: SessionKind::Support, device_id: String::new(), ..viewer_ctx(None) });
    drive(&mut host, &mut viewer, hello, &mut store, Script { secret: entered, consent })
}

#[test]
fn support_code_with_consent() {
    let (h, w) = support("905172386413", "905172386413", true);
    assert!(matches!(h, Some(End::Ok { method: AuthMethod::SupportCode, .. })), "{h:?}");
    assert!(matches!(w, Some(End::Ok { method: AuthMethod::SupportCode, .. })), "{w:?}");
}

#[test]
fn support_code_denied_or_wrong() {
    let (h, w) = support("905172386413", "905172386413", false);
    assert_eq!((h, w), (Some(End::Fail(Failure::ConsentDenied)), Some(End::Fail(Failure::ConsentDenied))));
    let (h, _) = support("905172386413", "905172386414", true);
    assert!(matches!(h, Some(End::Fail(Failure::BadSecret { method: AuthMethod::SupportCode, .. }))), "{h:?}");
}

#[test]
fn support_refused_when_no_code_active() {
    let mut store = Store::default();
    let mut host = HostHandshake::new(HostContext { transport_viewer_device: None, ..host_ctx(Some(PinVerifier::create(PIN).unwrap())) });
    let (mut viewer, hello) =
        ViewerHandshake::new(ViewerContext { kind: SessionKind::Support, device_id: String::new(), ..viewer_ctx(None) });
    let (h, _) = drive(&mut host, &mut viewer, hello, &mut store, Script { secret: "905172386413", consent: true });
    assert_eq!(h, Some(End::Fail(Failure::NotAllowed)), "a PIN must never be usable for a support session");
}

#[test]
fn viewer_does_not_trust_success_without_proof() {
    // A fake host that skips SPAKE2 and claims success.
    let (mut viewer, _hello) = ViewerHandshake::new(viewer_ctx(None));
    let ack = Envelope {
        msg: Some(Msg::HelloAck(moonrd_session::proto::HelloAck {
            protocol_version: 1,
            auth_method: AuthMethod::Pin as i32,
            pin_salt: vec![1; 16],
            argon2: Some(moonrd_session::pin::KdfParams::default().to_proto()),
            ..Default::default()
        })),
    };
    assert!(matches!(viewer.on_message(ack), Outcome::NeedSecret { .. }));
    let _ = viewer.provide_secret(PIN);
    let ok = Envelope { msg: Some(Msg::AuthResult(AuthResult { status: AuthStatus::Ok as i32, ..Default::default() })) };
    assert!(matches!(viewer.on_message(ok), Outcome::Failed { failure: Failure::Protocol(_), .. }));
}

#[test]
fn viewer_rejects_downgrade_and_hostile_params() {
    // Host picks pairing although the viewer holds none.
    let (mut viewer, _) = ViewerHandshake::new(viewer_ctx(None));
    let ack = |method: AuthMethod, mem: u32| Envelope {
        msg: Some(Msg::HelloAck(moonrd_session::proto::HelloAck {
            protocol_version: 1,
            auth_method: method as i32,
            pin_salt: vec![1; 16],
            argon2: Some(moonrd_session::proto::Argon2Params { memory_kib: mem, iterations: 2, parallelism: 1 }),
            ..Default::default()
        })),
    };
    assert!(matches!(viewer.on_message(ack(AuthMethod::Pairing, 19_456)), Outcome::Failed { failure: Failure::Protocol(_), .. }));
    let (mut viewer, _) = ViewerHandshake::new(viewer_ctx(None));
    assert!(matches!(viewer.on_message(ack(AuthMethod::Pin, 8 << 20)), Outcome::Failed { failure: Failure::Protocol(_), .. }));
}

#[test]
fn bad_pin_format_does_not_cost_an_attempt() {
    let v = PinVerifier::create(PIN).unwrap();
    let mut store = Store::default();
    let mut host = HostHandshake::new(host_ctx(Some(v)));
    let (mut viewer, hello) = ViewerHandshake::new(viewer_ctx(None));
    let Outcome::Continue(out) = host.on_message(hello, &mut store) else { panic!() };
    let mut out = VecDeque::from(out);
    assert!(matches!(viewer.on_message(out.pop_front().unwrap()), Outcome::NeedSecret { .. }));
    assert!(matches!(viewer.provide_secret("12"), Outcome::Failed { failure: Failure::Protocol(_), .. }));
    // The viewer may retry with a well-formed PIN in the same handshake.
    assert!(matches!(viewer.provide_secret(PIN), Outcome::Continue(_)));
}
