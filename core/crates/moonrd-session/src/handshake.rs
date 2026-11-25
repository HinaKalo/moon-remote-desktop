//! Session handshake as two sans-IO state machines.
//!
//! The caller moves `Envelope`s between the transport and these objects; nothing here
//! does I/O or blocks, so the same code serves QUIC, WebRTC and tests.
//!
//! ```text
//! viewer → host    Hello
//! host   → viewer  HelloAck, AuthMessage.spake2_message            (or HelloAck + AuthResult refusal)
//! viewer → host    AuthMessage.spake2_message, AuthMessage.key_confirmation
//! host   → viewer  AuthMessage.key_confirmation
//! host   → viewer  AuthResult                                        (support: after the host user consents)
//! ```
//!
//! Method choice on the host (remote access): a valid pairing for the transport-proven
//! viewer device first, else the PIN. Support sessions use the support code and need
//! the host user's consent after the code checks out. PIN attempts go through
//! [`Lockout`], which is persisted before the PAKE runs; if persisting fails the
//! attempt is refused (fail closed).

use moonrd_proto::{
    auth_message::Step, envelope::Msg, AuthMessage, AuthMethod, AuthResult, AuthStatus, Bye, ByeReason, Codec, Envelope, Hello,
    HelloAck, PairingGrant, SessionKind, PROTOCOL_VERSION,
};

use crate::lockout::{Admission, Lockout, Policy};
use crate::pairing::Pairings;
use crate::pake::{ChannelBinding, Keys, Pake, Role};
use crate::pin::{KdfParams, PinVerifier, Secret};

// ------------------------------------------------------------------ messages

fn env(msg: Msg) -> Envelope {
    Envelope { msg: Some(msg) }
}

fn auth(step: Step) -> Envelope {
    env(Msg::Auth(AuthMessage { step: Some(step) }))
}

fn result(status: AuthStatus, remaining: u32, lockout: u32) -> Envelope {
    env(Msg::AuthResult(AuthResult { status: status as i32, remaining_attempts: remaining, lockout_seconds: lockout }))
}

fn bye(reason: ByeReason) -> Envelope {
    env(Msg::Bye(Bye { reason: reason as i32, resume_token: Vec::new() }))
}

/// Why a handshake ended without a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Wrong PIN / code / pairing key. `remaining` more PIN failures are allowed before a
    /// lockout; `lockout_secs` > 0 means the host is now locked.
    BadSecret { method: AuthMethod, remaining: u32, lockout_secs: u32 },
    LockedOut { retry_after: u32 },
    ConsentDenied,
    /// Not allowed at all: no PIN set, unknown device, method not offered.
    NotAllowed,
    /// The peer broke the protocol (unexpected message, bad version, malformed data).
    Protocol(String),
    /// The host could not persist its lockout state.
    Storage(String),
}

/// Information the host learns about the viewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerInfo {
    pub kind: SessionKind,
    pub device_id: String,
    pub display_name: String,
    pub client_version: String,
}

/// Information the viewer learns about the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub device_id: String,
    pub display_name: String,
    pub version: String,
}

/// A successfully authenticated session.
pub struct Established<P> {
    pub method: AuthMethod,
    pub session_key: [u8; 32],
    pub peer: P,
}

impl<P: std::fmt::Debug> std::fmt::Debug for Established<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established").field("method", &self.method).field("peer", &self.peer).finish_non_exhaustive()
    }
}

/// What to do after feeding a message in.
#[derive(Debug)]
pub enum Outcome<P> {
    /// Send these and keep going.
    Continue(Vec<Envelope>),
    /// Viewer only: ask the user for the PIN or support code, then call
    /// [`ViewerHandshake::provide_secret`]. Send `out` first.
    NeedSecret { method: AuthMethod, out: Vec<Envelope> },
    /// Host only: the support code checked out; ask the host user whether to let
    /// `viewer` in, then call [`HostHandshake::consent`].
    NeedConsent { viewer: ViewerInfo },
    /// Done: send `out`, then the session is live.
    Established { out: Vec<Envelope>, session: Established<P> },
    /// Done: send `out`, then close the connection.
    Failed { out: Vec<Envelope>, failure: Failure },
}

fn protocol<P>(why: impl Into<String>) -> Outcome<P> {
    Outcome::Failed { out: vec![bye(ByeReason::ProtocolError)], failure: Failure::Protocol(why.into()) }
}

// ------------------------------------------------------------------ host

/// Persistent host state the handshake reads and updates.
pub trait HostStore {
    /// Unix seconds.
    fn now(&self) -> u64;
    fn lockout(&mut self) -> &mut Lockout;
    fn pairings(&mut self) -> &mut Pairings;
    /// Writes lockout and pairings to durable storage.
    fn persist(&mut self) -> Result<(), String>;
}

/// Static facts for one incoming connection.
pub struct HostContext {
    pub host_device_id: String,
    pub host_display_name: String,
    pub host_version: String,
    pub binding: ChannelBinding,
    /// Viewer device proven by the transport (QUIC raw public key mapped through the
    /// device list). `None` for WebRTC, where the viewer is not authenticated yet.
    pub transport_viewer_device: Option<String>,
    /// The host PIN; `None` if not set, which refuses PIN logins.
    pub pin: Option<PinVerifier>,
    /// The currently valid support code, if the host user requested one.
    pub support_code: Option<PinVerifier>,
    pub policy: Policy,
}

enum HostState {
    AwaitHello,
    AwaitSpake { pake: Pake, method: AuthMethod, pairing_id: Vec<u8>, remaining: u32, viewer: ViewerInfo },
    AwaitConfirm { keys: Keys, method: AuthMethod, pairing_id: Vec<u8>, remaining: u32, viewer: ViewerInfo },
    AwaitConsent { keys: Keys, viewer: ViewerInfo },
    Done,
}

/// Host side of one handshake.
pub struct HostHandshake {
    ctx: HostContext,
    state: HostState,
}

impl HostHandshake {
    pub fn new(ctx: HostContext) -> Self {
        Self { ctx, state: HostState::AwaitHello }
    }

    /// Feeds one message from the viewer.
    pub fn on_message(&mut self, msg: Envelope, store: &mut dyn HostStore) -> Outcome<ViewerInfo> {
        let state = std::mem::replace(&mut self.state, HostState::Done);
        match (state, msg.msg) {
            (HostState::AwaitHello, Some(Msg::Hello(h))) => self.on_hello(h, store),
            (HostState::AwaitSpake { pake, method, pairing_id, remaining, viewer }, Some(Msg::Auth(AuthMessage { step: Some(Step::Spake2Message(m)) }))) => {
                match pake.finish(&m) {
                    Ok(keys) => {
                        let out = vec![auth(Step::KeyConfirmation(keys.confirmation().to_vec()))];
                        self.state = HostState::AwaitConfirm { keys, method, pairing_id, remaining, viewer };
                        Outcome::Continue(out)
                    }
                    Err(e) => protocol(e.to_string()),
                }
            }
            (HostState::AwaitConfirm { keys, method, pairing_id, remaining, viewer }, Some(Msg::Auth(AuthMessage { step: Some(Step::KeyConfirmation(tag)) }))) => {
                self.on_confirm(keys, &tag, method, &pairing_id, remaining, viewer, store)
            }
            (HostState::Done, _) => protocol("handshake already finished"),
            (_, other) => protocol(format!("unexpected message {:?}", other.map(|m| std::mem::discriminant(&m)))),
        }
    }

    /// Host user's answer for a support session.
    pub fn consent(&mut self, granted: bool) -> Outcome<ViewerInfo> {
        match std::mem::replace(&mut self.state, HostState::Done) {
            HostState::AwaitConsent { keys, viewer } if granted => Outcome::Established {
                out: vec![result(AuthStatus::Ok, 0, 0)],
                session: Established { method: AuthMethod::SupportCode, session_key: *keys.session_key(), peer: viewer },
            },
            HostState::AwaitConsent { .. } => {
                Outcome::Failed { out: vec![result(AuthStatus::ConsentDenied, 0, 0)], failure: Failure::ConsentDenied }
            }
            _ => protocol("consent outside a support handshake"),
        }
    }

    fn ack(&self, method: AuthMethod, salt: &[u8], params: Option<KdfParams>, lockout: u32) -> Envelope {
        env(Msg::HelloAck(HelloAck {
            protocol_version: PROTOCOL_VERSION,
            host_device_id: self.ctx.host_device_id.clone(),
            host_display_name: self.ctx.host_display_name.clone(),
            host_version: self.ctx.host_version.clone(),
            auth_method: method as i32,
            pin_salt: salt.to_vec(),
            argon2: params.map(KdfParams::to_proto),
            lockout_seconds: lockout,
        }))
    }

    fn refuse(&self, status: AuthStatus, failure: Failure, lockout: u32) -> Outcome<ViewerInfo> {
        Outcome::Failed {
            out: vec![self.ack(AuthMethod::Unspecified, &[], None, lockout), result(status, 0, lockout)],
            failure,
        }
    }

    fn on_hello(&mut self, h: Hello, store: &mut dyn HostStore) -> Outcome<ViewerInfo> {
        if h.protocol_version != PROTOCOL_VERSION {
            return protocol(format!("unsupported protocol version {}", h.protocol_version));
        }
        let kind = SessionKind::try_from(h.kind).unwrap_or(SessionKind::Unspecified);
        if let Some(proven) = &self.ctx.transport_viewer_device
            && &h.viewer_device_id != proven
        {
            return self.refuse(AuthStatus::NotAllowed, Failure::NotAllowed, 0);
        }
        let offered = |m: AuthMethod| h.auth_methods.contains(&(m as i32));
        let viewer = ViewerInfo {
            kind,
            device_id: h.viewer_device_id.clone(),
            display_name: h.viewer_display_name.chars().filter(|c| !c.is_control()).take(64).collect(),
            client_version: h.client_version.chars().take(64).collect(),
        };

        let (method, secret, salt, params, remaining, pairing_id) = match kind {
            SessionKind::Support => {
                let Some(code) = &self.ctx.support_code else { return self.refuse(AuthStatus::NotAllowed, Failure::NotAllowed, 0) };
                if !offered(AuthMethod::SupportCode) {
                    return self.refuse(AuthStatus::NotAllowed, Failure::NotAllowed, 0);
                }
                (AuthMethod::SupportCode, code.secret(), code.salt.to_vec(), Some(code.params), 0, Vec::new())
            }
            SessionKind::RemoteAccess => {
                let paired = if offered(AuthMethod::Pairing) && !h.pairing_id.is_empty() && !h.viewer_device_id.is_empty() {
                    store.pairings().secret_for(&h.pairing_id, &h.viewer_device_id)
                } else {
                    None
                };
                if let Some(secret) = paired {
                    (AuthMethod::Pairing, secret, Vec::new(), None, 0, h.pairing_id.clone())
                } else if let (Some(pin), true) = (&self.ctx.pin, offered(AuthMethod::Pin)) {
                    let (secret, salt, params) = (pin.secret(), pin.salt.to_vec(), pin.params);
                    let policy = self.ctx.policy;
                    let now = store.now();
                    match store.lockout().begin(now, &policy) {
                        Admission::Locked { retry_after } => {
                            let secs = u32::try_from(retry_after).unwrap_or(u32::MAX);
                            return self.refuse(AuthStatus::LockedOut, Failure::LockedOut { retry_after: secs }, secs);
                        }
                        Admission::Allowed { remaining } => {
                            if let Err(e) = store.persist() {
                                return Outcome::Failed { out: vec![bye(ByeReason::HostShutdown)], failure: Failure::Storage(e) };
                            }
                            (AuthMethod::Pin, secret, salt, Some(params), remaining, Vec::new())
                        }
                    }
                } else {
                    return self.refuse(AuthStatus::NotAllowed, Failure::NotAllowed, 0);
                }
            }
            SessionKind::Unspecified => return protocol("session kind missing"),
        };

        let (pake, msg) = Pake::start(Role::Host, method, &secret, &self.ctx.binding);
        let out = vec![self.ack(method, &salt, params, 0), auth(Step::Spake2Message(msg))];
        self.state = HostState::AwaitSpake { pake, method, pairing_id, remaining, viewer };
        Outcome::Continue(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_confirm(
        &mut self,
        keys: Keys,
        tag: &[u8],
        method: AuthMethod,
        pairing_id: &[u8],
        remaining: u32,
        viewer: ViewerInfo,
        store: &mut dyn HostStore,
    ) -> Outcome<ViewerInfo> {
        if keys.verify_peer(tag).is_err() {
            let now = store.now();
            let lockout = if method == AuthMethod::Pin { store.lockout().retry_after(now) } else { 0 };
            let lockout = u32::try_from(lockout).unwrap_or(u32::MAX);
            return Outcome::Failed {
                out: vec![result(AuthStatus::BadSecret, remaining, lockout)],
                failure: Failure::BadSecret { method, remaining, lockout_secs: lockout },
            };
        }
        match method {
            AuthMethod::Pin => store.lockout().succeeded(),
            AuthMethod::Pairing => {
                let now = store.now();
                store.pairings().touch(pairing_id, now);
            }
            AuthMethod::SupportCode => {
                let out_viewer = viewer.clone();
                self.state = HostState::AwaitConsent { keys, viewer };
                return Outcome::NeedConsent { viewer: out_viewer };
            }
            AuthMethod::Unspecified => return protocol("no method"),
        }
        if let Err(e) = store.persist() {
            // Authenticated, but the reset/touch could not be saved: refuse rather than
            // leave the host's state inconsistent with what the viewer was told.
            return Outcome::Failed { out: vec![bye(ByeReason::HostShutdown)], failure: Failure::Storage(e) };
        }
        Outcome::Established {
            out: vec![result(AuthStatus::Ok, 0, 0)],
            session: Established { method, session_key: *keys.session_key(), peer: viewer },
        }
    }
}

/// Host: answers a `PairingRequest` received on an established session. Pairing is
/// only granted to a known device that authenticated with the PIN; otherwise the reply
/// is an empty grant (declined).
pub fn grant_pairing(method: AuthMethod, viewer: &ViewerInfo, label: &str, store: &mut dyn HostStore) -> Envelope {
    if method != AuthMethod::Pin || viewer.device_id.is_empty() {
        return auth(Step::PairingGrant(PairingGrant::default()));
    }
    let now = store.now();
    let p = store.pairings().grant(&viewer.device_id, label, now);
    if store.persist().is_err() {
        store.pairings().revoke(&p.id);
        return auth(Step::PairingGrant(PairingGrant::default()));
    }
    auth(Step::PairingGrant(PairingGrant { pairing_id: p.id.to_vec(), pairing_key: p.key.to_vec() }))
}

// ------------------------------------------------------------------ viewer

/// A pairing the viewer holds for one host.
#[derive(Clone)]
pub struct HeldPairing {
    pub id: Vec<u8>,
    pub key: [u8; 32],
}

/// Static facts for one outgoing connection.
pub struct ViewerContext {
    pub kind: SessionKind,
    /// Empty for web viewers.
    pub device_id: String,
    pub display_name: String,
    pub client_version: String,
    pub binding: ChannelBinding,
    pub pairing: Option<HeldPairing>,
}

enum ViewerState {
    AwaitAck,
    NeedSecret { method: AuthMethod, salt: Vec<u8>, params: KdfParams, host_msg: Option<Vec<u8>> },
    AwaitHostSpake { pake: Pake, method: AuthMethod },
    AwaitHostConfirm { keys: Keys, method: AuthMethod },
    AwaitResult { keys: Option<Keys>, method: AuthMethod },
    Done,
}

/// Viewer side of one handshake.
pub struct ViewerHandshake {
    ctx: ViewerContext,
    host: Option<HostInfo>,
    state: ViewerState,
}

impl ViewerHandshake {
    /// Starts the handshake; send the returned `Hello`.
    pub fn new(ctx: ViewerContext) -> (Self, Envelope) {
        let mut methods = Vec::new();
        match ctx.kind {
            SessionKind::Support => methods.push(AuthMethod::SupportCode as i32),
            _ => {
                if ctx.pairing.is_some() {
                    methods.push(AuthMethod::Pairing as i32);
                }
                methods.push(AuthMethod::Pin as i32);
            }
        }
        let hello = env(Msg::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            kind: ctx.kind as i32,
            viewer_device_id: ctx.device_id.clone(),
            viewer_display_name: ctx.display_name.clone(),
            client_version: ctx.client_version.clone(),
            codecs: vec![Codec::H264 as i32],
            auth_methods: methods,
            pairing_id: ctx.pairing.as_ref().map(|p| p.id.clone()).unwrap_or_default(),
        }));
        (Self { ctx, host: None, state: ViewerState::AwaitAck }, hello)
    }

    /// The host, once `HelloAck` arrived.
    pub fn host(&self) -> Option<&HostInfo> {
        self.host.as_ref()
    }

    /// Feeds one message from the host.
    pub fn on_message(&mut self, msg: Envelope) -> Outcome<HostInfo> {
        let state = std::mem::replace(&mut self.state, ViewerState::Done);
        match (state, msg.msg) {
            (ViewerState::AwaitAck, Some(Msg::HelloAck(a))) => self.on_ack(a),
            (ViewerState::NeedSecret { method, salt, params, host_msg: None }, Some(Msg::Auth(AuthMessage { step: Some(Step::Spake2Message(m)) }))) => {
                // Arrived while the user is still typing; keep it for provide_secret.
                self.state = ViewerState::NeedSecret { method, salt, params, host_msg: Some(m) };
                Outcome::Continue(Vec::new())
            }
            (ViewerState::AwaitHostSpake { pake, method }, Some(Msg::Auth(AuthMessage { step: Some(Step::Spake2Message(m)) }))) => {
                self.finish_pake(pake, method, &m, Vec::new())
            }
            (ViewerState::AwaitHostConfirm { keys, method }, Some(Msg::Auth(AuthMessage { step: Some(Step::KeyConfirmation(tag)) }))) => {
                // Remember whether the host proved knowledge of the secret; an AuthResult
                // "ok" without that proof is not trusted.
                let keys = keys.verify_peer(&tag).is_ok().then_some(keys);
                self.state = ViewerState::AwaitResult { keys, method };
                Outcome::Continue(Vec::new())
            }
            (ViewerState::AwaitResult { keys, method }, Some(Msg::AuthResult(r))) => self.on_result(r, keys, method),
            // Refusals and failures may arrive in any state before the result.
            (_, Some(Msg::AuthResult(r))) if r.status != AuthStatus::Ok as i32 => self.on_result(r, None, AuthMethod::Unspecified),
            (_, Some(Msg::Bye(_))) => Outcome::Failed { out: Vec::new(), failure: Failure::Protocol("host closed the session".into()) },
            (ViewerState::Done, _) => protocol("handshake already finished"),
            (_, other) => protocol(format!("unexpected message {:?}", other.map(|m| std::mem::discriminant(&m)))),
        }
    }

    /// Supplies the PIN or support code after [`Outcome::NeedSecret`]. Runs Argon2id,
    /// so call it off the UI thread.
    pub fn provide_secret(&mut self, code: &str) -> Outcome<HostInfo> {
        let ViewerState::NeedSecret { method, salt, params, host_msg } = std::mem::replace(&mut self.state, ViewerState::Done) else {
            return protocol("no secret was requested");
        };
        let secret = match Secret::derive(code, &salt, params) {
            Ok(s) => s,
            Err(e) => {
                // Bad input (e.g. too short): ask again without spending a host attempt.
                self.state = ViewerState::NeedSecret { method, salt, params, host_msg };
                return Outcome::Failed { out: Vec::new(), failure: Failure::Protocol(format!("invalid input: {e}")) };
            }
        };
        self.start_pake(method, &secret, host_msg)
    }

    fn on_ack(&mut self, a: HelloAck) -> Outcome<HostInfo> {
        if a.protocol_version != PROTOCOL_VERSION {
            return protocol(format!("unsupported protocol version {}", a.protocol_version));
        }
        self.host = Some(HostInfo { device_id: a.host_device_id, display_name: a.host_display_name, version: a.host_version });
        let method = AuthMethod::try_from(a.auth_method).unwrap_or(AuthMethod::Unspecified);
        let expected_ok = match (self.ctx.kind, method) {
            (SessionKind::Support, AuthMethod::SupportCode) => true,
            (SessionKind::RemoteAccess, AuthMethod::Pin) => true,
            (SessionKind::RemoteAccess, AuthMethod::Pairing) => self.ctx.pairing.is_some(),
            _ => false,
        };
        if !expected_ok {
            // Unspecified method means a refusal follows (AuthResult); anything else is a
            // downgrade attempt or a confused host.
            if method == AuthMethod::Unspecified {
                self.state = ViewerState::AwaitResult { keys: None, method };
                return Outcome::Continue(Vec::new());
            }
            return protocol("host chose a method this viewer did not offer");
        }
        if method == AuthMethod::Pairing {
            let key = self.ctx.pairing.as_ref().map(|p| p.key).expect("checked above");
            return self.start_pake(method, &Secret::from_key(key), None);
        }
        let params = a.argon2.as_ref().map(KdfParams::from_proto).unwrap_or_default();
        if !params.is_reasonable() || a.pin_salt.len() < 8 {
            return protocol("unreasonable key-derivation parameters");
        }
        self.state = ViewerState::NeedSecret { method, salt: a.pin_salt, params, host_msg: None };
        Outcome::NeedSecret { method, out: Vec::new() }
    }

    fn start_pake(&mut self, method: AuthMethod, secret: &Secret, host_msg: Option<Vec<u8>>) -> Outcome<HostInfo> {
        let (pake, msg) = Pake::start(Role::Viewer, method, secret, &self.ctx.binding);
        let out = vec![auth(Step::Spake2Message(msg))];
        match host_msg {
            Some(m) => self.finish_pake(pake, method, &m, out),
            None => {
                self.state = ViewerState::AwaitHostSpake { pake, method };
                Outcome::Continue(out)
            }
        }
    }

    fn finish_pake(&mut self, pake: Pake, method: AuthMethod, host_msg: &[u8], mut out: Vec<Envelope>) -> Outcome<HostInfo> {
        match pake.finish(host_msg) {
            Ok(keys) => {
                out.push(auth(Step::KeyConfirmation(keys.confirmation().to_vec())));
                self.state = ViewerState::AwaitHostConfirm { keys, method };
                Outcome::Continue(out)
            }
            Err(e) => protocol(e.to_string()),
        }
    }

    fn on_result(&mut self, r: AuthResult, keys: Option<Keys>, method: AuthMethod) -> Outcome<HostInfo> {
        let status = AuthStatus::try_from(r.status).unwrap_or(AuthStatus::Unspecified);
        let failure = match status {
            AuthStatus::Ok => match (keys, self.host.clone()) {
                (Some(keys), Some(host)) => {
                    return Outcome::Established {
                        out: Vec::new(),
                        session: Established { method, session_key: *keys.session_key(), peer: host },
                    };
                }
                _ => Failure::Protocol("host reported success without proving the secret".into()),
            },
            AuthStatus::BadSecret => Failure::BadSecret { method, remaining: r.remaining_attempts, lockout_secs: r.lockout_seconds },
            AuthStatus::LockedOut => Failure::LockedOut { retry_after: r.lockout_seconds },
            AuthStatus::ConsentDenied => Failure::ConsentDenied,
            AuthStatus::NotAllowed => Failure::NotAllowed,
            AuthStatus::Unspecified => Failure::Protocol("unknown auth status".into()),
        };
        Outcome::Failed { out: Vec::new(), failure }
    }
}
