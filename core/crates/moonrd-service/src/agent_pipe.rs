//! SYSTEM-only pipe protocol between `moonrd-service` and the in-session `moonrd-agent`.
//!
//! Messages on the pipe are varint length-delimited [`moonrd_proto::Envelope`] frames
//! (identical to the QUIC control stream, encoded with [`moonrd_session::frame`]). That
//! avoids any double-serialization or base64 overhead for H.264 `VideoFrame`s.
//!
//! When the console session switches (logon screen ↔ user desktop, fast user switching),
//! the old agent exits and a new agent connects to this pipe. [`AgentBridge`] keeps the
//! viewer's session alive across the transition: it notifies the viewer with
//! `Notice(SESSION_SWITCHING)` when the agent drops and sends `KeyframeRequest` to the
//! new agent as soon as it connects.

use std::{collections::BTreeMap, io};
use std::sync::{Arc, Mutex};

use moonrd_proto::envelope::Msg;
use moonrd_proto::{Envelope, KeyEvent, KeyframeRequest, Notice, NoticeKind};
use moonrd_session::frame::{self, Decoder};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

/// Production agent pipe name (SYSTEM-only ACL).
pub const AGENT_PIPE_NAME: &str = r"\\.\pipe\moonrd-agent";
/// Development/console-mode agent pipe name (current user + SYSTEM).
pub const DEV_AGENT_PIPE_NAME: &str = r"\\.\pipe\moonrd-agent-dev";
/// SDDL allowing only LocalSystem.
pub const AGENT_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)";

const CHANNEL_CAPACITY: usize = 128;
const VIEWER_QUEUE_CAPACITY: usize = 12;

fn keyframe_request() -> Envelope {
    Envelope { msg: Some(Msg::KeyframeRequest(KeyframeRequest { last_good_sequence: 0 })) }
}

fn session_switching_notice() -> Envelope {
    Envelope {
        msg: Some(Msg::Notice(Notice {
            kind: NoticeKind::SessionSwitching as i32,
            message: "desktop session switching".into(),
        })),
    }
}

struct BridgeInner {
    display_list: Option<Envelope>,
    video_config: Option<Envelope>,
    /// Outbound channel to the currently connected agent.
    agent_tx: Option<mpsc::Sender<AgentCommand>>,
    /// Outbound channel to the currently attached viewer.
    viewer_tx: Option<mpsc::Sender<Envelope>>,
    /// Monotonic token so a detaching old viewer never clears a newer viewer's slot.
    viewer_id: u64,
    held_keys: BTreeMap<(u32, bool), KeyEvent>,
    video_interrupted: bool,
    keyframe_requested: bool,
}

enum AgentCommand {
    Message(Envelope),
    ReleaseKeys(Vec<KeyEvent>),
}

impl BridgeInner {
    fn release_keys(&mut self) {
        let keys = std::mem::take(&mut self.held_keys);
        if let Some(tx) = &self.agent_tx && !keys.is_empty() {
            let released = keys.into_values().map(|mut k| { k.pressed = false; k }).collect();
            let _ = tx.try_send(AgentCommand::ReleaseKeys(released));
        }
    }
}

/// Coordinates message passing between the single active in-session agent and the
/// single active remote viewer.
#[derive(Clone)]
pub struct AgentBridge {
    inner: Arc<Mutex<BridgeInner>>,
}

/// Active viewer's handle into the [`AgentBridge`]. Automatically detaches on drop.
pub struct ViewerAttachment {
    pub input: ViewerInput,
    pub from_agent: mpsc::Receiver<Envelope>,
}

/// Keeps the input lease alive independently of the viewer's media receiver.
pub struct ViewerInput {
    bridge: AgentBridge,
    id: u64,
}

impl ViewerAttachment {
    pub fn send_to_agent(&self, msg: Envelope) -> bool {
        self.input.send_to_agent(msg)
    }
}

impl ViewerInput {
    /// Forwards an `Envelope` from the viewer to the agent (dropped if no agent is
    /// currently connected, e.g. mid-session-switch).
    pub fn send_to_agent(&self, msg: Envelope) -> bool {
        let mut g = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.viewer_id != self.id { return false; }
        let Some(tx) = &g.agent_tx else { return false; };
        let key = match &msg.msg {
            Some(Msg::Key(key)) if key.text.is_empty() && key.scancode != 0 => Some(key.clone()),
            _ => None,
        };
        let motion = matches!(&msg.msg, Some(Msg::Pointer(p)) if p.button == 0 && p.wheel_x == 0 && p.wheel_y == 0);
        // Pointer motion can be dropped under load. Keep room for key/button changes
        // and a final batch of key releases at disconnect.
        let reserved = if motion { 8 } else { 1 };
        if tx.capacity() <= reserved || tx.try_send(AgentCommand::Message(msg)).is_err() { return false; }
        if let Some(key) = key {
            let id = (key.scancode, key.extended);
            if key.pressed { g.held_keys.insert(id, key); } else { g.held_keys.remove(&id); }
        }
        true
    }
}

impl Drop for ViewerInput {
    fn drop(&mut self) {
        let mut g = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.viewer_id == self.id {
            g.release_keys();
            g.viewer_tx = None;
        }
    }
}

impl Default for AgentBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentBridge {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(BridgeInner { agent_tx: None, viewer_tx: None, viewer_id: 0,
            display_list: None, video_config: None, held_keys: BTreeMap::new(),
            video_interrupted: false, keyframe_requested: false })) }
    }

    /// True when an in-session agent is currently connected on the pipe.
    pub fn agent_connected(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).agent_tx.is_some()
    }

    /// True when a remote viewer is currently attached.
    pub fn viewer_attached(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).viewer_tx.is_some()
    }

    /// Attaches a viewer session, replacing any previous viewer (whose receiver will
    /// close). Requests an immediate keyframe if an agent is already connected.
    pub fn attach_viewer(&self) -> ViewerAttachment {
        let (tx, rx) = mpsc::channel(VIEWER_QUEUE_CAPACITY);
        let id = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.release_keys();
            g.viewer_id += 1;
            g.video_interrupted = false;
            g.keyframe_requested = false;
            // The agent announces the display and codec when it starts. Replay both
            // before forwarding frames to viewers that attach later.
            for metadata in [&g.display_list, &g.video_config].into_iter().flatten() {
                let _ = tx.try_send(metadata.clone());
            }
            g.viewer_tx = Some(tx);
            if let Some(agent) = &g.agent_tx && agent.capacity() > 1 {
                let _ = agent.try_send(AgentCommand::Message(keyframe_request()));
            }
            g.viewer_id
        };
        ViewerAttachment { input: ViewerInput { bridge: self.clone(), id }, from_agent: rx }
    }

    fn set_agent(&self, tx: mpsc::Sender<AgentCommand>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.viewer_tx.is_some() {
            let _ = tx.try_send(AgentCommand::Message(keyframe_request()));
        }
        g.agent_tx = Some(tx);
    }

    fn clear_agent(&self) {
        let viewer_tx = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.agent_tx = None;
            g.held_keys.clear();
            g.display_list = None;
            g.video_config = None;
            g.video_interrupted = false;
            g.keyframe_requested = false;
            g.viewer_tx.clone()
        };
        if let Some(viewer) = viewer_tx {
            let _ = viewer.try_send(session_switching_notice());
        }
    }

    fn forward_to_viewer(&self, msg: Envelope) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match msg.msg {
            Some(Msg::DisplayList(_)) => g.display_list = Some(msg.clone()),
            Some(Msg::VideoConfig(_)) => g.video_config = Some(msg.clone()),
            _ => {}
        }
        let Some(viewer) = g.viewer_tx.clone() else { return; };
        if let Some(Msg::VideoFrame(frame)) = &msg.msg {
            // Reserve room for display/codec metadata and notices. After a drop,
            // delta frames cannot start a new decode chain.
            if viewer.capacity() <= 3 {
                g.video_interrupted = true;
                g.keyframe_requested = false;
                return;
            }
            if g.video_interrupted && !frame.keyframe {
                if !g.keyframe_requested && let Some(agent) = &g.agent_tx && agent.capacity() > 1 {
                    g.keyframe_requested = agent.try_send(AgentCommand::Message(keyframe_request())).is_ok();
                }
                return;
            }
            g.video_interrupted = false;
            g.keyframe_requested = false;
        }
        let _ = viewer.try_send(msg);
    }
}

/// Serves one connected agent stream until it closes or `shutdown` fires.
pub async fn serve_stream<S>(stream: S, bridge: AgentBridge, mut shutdown: watch::Receiver<bool>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (to_agent_tx, mut to_agent_rx) = mpsc::channel(CHANNEL_CAPACITY);
    bridge.set_agent(to_agent_tx);

    let send_inputs = async {
        while let Some(cmd) = to_agent_rx.recv().await {
            let encoded = match cmd {
                AgentCommand::Message(msg) => frame::encode(&msg),
                AgentCommand::ReleaseKeys(keys) => keys.into_iter()
                    .flat_map(|key| frame::encode(&Envelope { msg: Some(Msg::Key(key)) }))
                    .collect(),
            };
            writer.write_all(&encoded).await?;
        }
        Ok(())
    };
    let read_agent = async {
        let mut decoder = Decoder::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 { return Ok(()); }
            decoder.push(&buf[..n]);
            while let Some(env) = decoder.next_frame().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))? {
                bridge.forward_to_viewer(env);
            }
        }
    };
    let res = tokio::select! {
        _ = shutdown.changed() => Ok(()),
        result = send_inputs => result,
        result = read_agent => result,
    };
    bridge.clear_agent();
    res
}

/// Windows named-pipe server for the in-session agent.
#[cfg(windows)]
pub mod server {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::*;
    use crate::win::SecurityDescriptor;

    pub struct Options {
        pub name: String,
        pub sddl: String,
    }

    fn create(opts: &Options, sd: &SecurityDescriptor, first: bool) -> io::Result<NamedPipeServer> {
        let mut sa = sd.attributes();
        let mut o = ServerOptions::new();
        // Only one agent runs at a time, allow 2 instances so a new agent can connect
        // while the old one is tearing down.
        o.first_pipe_instance(first).reject_remote_clients(true).max_instances(2);
        // SAFETY: `sa` points at `sd`, which outlives the call.
        unsafe { o.create_with_security_attributes_raw(&opts.name, &mut sa as *mut _ as *mut std::ffi::c_void) }
    }

    pub async fn serve(opts: Options, bridge: AgentBridge, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let sd = SecurityDescriptor::from_sddl(&opts.sddl)?;
        let mut server = create(&opts, &sd, true)?;
        loop {
            tokio::select! {
                r = server.connect() => r?,
                _ = shutdown.changed() => return Ok(()),
            }
            let conn = server;
            server = create(&opts, &sd, false)?;
            let bridge = bridge.clone();
            let stop = shutdown.clone();
            tokio::spawn(async move {
                let _ = serve_stream(conn, bridge, stop).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moonrd_proto::{ClipboardData, PointerButton, PointerEvent};

    async fn read_envelope<R: AsyncRead + Unpin>(r: &mut R, dec: &mut Decoder) -> Envelope {
        let mut buf = [0u8; 4096];
        loop {
            if let Some(m) = dec.next_frame().unwrap() {
                return m;
            }
            let n = r.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected eof");
            dec.push(&buf[..n]);
        }
    }

    #[test]
    fn saturated_pipe_keeps_room_to_release_the_disconnected_viewers_keys() {
        let bridge = AgentBridge::new();
        let (tx, mut rx) = mpsc::channel(4);
        bridge.set_agent(tx);
        let viewer = bridge.attach_viewer();
        assert!(matches!(rx.try_recv(), Ok(AgentCommand::Message(Envelope { msg: Some(Msg::KeyframeRequest(_)) }))));
        let down = Envelope { msg: Some(Msg::Key(KeyEvent { scancode: 0xe0, pressed: true, ..Default::default() })) };
        let text = Envelope { msg: Some(Msg::Key(KeyEvent { text: "你好 한글".into(), ..Default::default() })) };
        assert!(viewer.send_to_agent(down.clone()));
        assert!(viewer.send_to_agent(down.clone())); // Auto-repeat still needs one key-up.
        assert!(viewer.send_to_agent(text.clone()));
        assert!(!viewer.send_to_agent(down.clone()));

        let _replacement = bridge.attach_viewer();
        assert!(!viewer.send_to_agent(down.clone()));
        drop(viewer);
        for expected in [down.clone(), down, text] {
            assert!(matches!(rx.try_recv(), Ok(AgentCommand::Message(msg)) if msg == expected));
        }
        let Ok(AgentCommand::ReleaseKeys(released)) = rx.try_recv() else { panic!("expected key release") };
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].scancode, 0xe0);
        assert!(!released[0].pressed);
    }

    #[test]
    fn skipped_video_waits_for_a_keyframe_and_preserves_display_metadata() {
        use moonrd_proto::{VideoConfig, VideoFrame};

        let bridge = AgentBridge::new();
        let (tx, mut requests) = mpsc::channel(4);
        bridge.set_agent(tx);
        let mut viewer = bridge.attach_viewer();
        let _ = requests.try_recv().unwrap();
        let frame = |sequence, keyframe| Envelope { msg: Some(Msg::VideoFrame(VideoFrame {
            sequence, keyframe, ..Default::default()
        })) };
        for sequence in 1..=VIEWER_QUEUE_CAPACITY as u64 {
            bridge.forward_to_viewer(frame(sequence, sequence == 1));
        }
        bridge.forward_to_viewer(Envelope { msg: Some(Msg::VideoConfig(VideoConfig {
            display_id: 2, ..Default::default()
        })) });
        for _ in 0..VIEWER_QUEUE_CAPACITY - 3 {
            assert!(matches!(viewer.from_agent.try_recv().unwrap().msg, Some(Msg::VideoFrame(_))));
        }
        assert!(matches!(viewer.from_agent.try_recv().unwrap().msg, Some(Msg::VideoConfig(config)) if config.display_id == 2));
        bridge.forward_to_viewer(frame(80, false));
        assert!(matches!(requests.try_recv(), Ok(AgentCommand::Message(Envelope { msg: Some(Msg::KeyframeRequest(_)) }))));
        assert!(viewer.from_agent.try_recv().is_err());
        bridge.forward_to_viewer(frame(81, true));
        assert!(matches!(viewer.from_agent.try_recv().unwrap().msg, Some(Msg::VideoFrame(frame)) if frame.sequence == 81));
    }

    #[tokio::test]
    async fn forwards_both_directions_and_survives_agent_restart() {
        let bridge = AgentBridge::new();
        let (stop_tx, stop_rx) = watch::channel(false);

        let (service_end, mut agent_end) = tokio::io::duplex(16 * 1024);
        let task1 = tokio::spawn(serve_stream(service_end, bridge.clone(), stop_rx.clone()));

        // Wait until agent is registered.
        while !bridge.agent_connected() {
            tokio::task::yield_now().await;
        }

        let mut viewer = bridge.attach_viewer();
        let mut agent_dec = Decoder::new();

        // Attaching viewer triggers KeyframeRequest to agent.
        let kf = read_envelope(&mut agent_end, &mut agent_dec).await;
        assert!(matches!(kf.msg, Some(Msg::KeyframeRequest(_))));

        // Viewer -> agent input.
        assert!(viewer.send_to_agent(Envelope {
            msg: Some(Msg::Pointer(PointerEvent {
                display_id: 1,
                x: 100,
                y: 200,
                button: PointerButton::Left as i32,
                pressed: true,
                wheel_x: 0,
                wheel_y: 0,
            })),
        }));
        let ptr = read_envelope(&mut agent_end, &mut agent_dec).await;
        assert!(matches!(ptr.msg, Some(Msg::Pointer(p)) if p.x == 100 && p.y == 200));

        // Agent -> viewer clipboard.
        let clip = Envelope { msg: Some(Msg::Clipboard(ClipboardData { text: "hello".into() })) };
        agent_end.write_all(&frame::encode(&clip)).await.unwrap();
        let got = viewer.from_agent.recv().await.unwrap();
        assert!(matches!(got.msg, Some(Msg::Clipboard(c)) if c.text == "hello"));

        // Agent disconnects (session switch) -> viewer receives SessionSwitching notice.
        drop(agent_end);
        task1.await.unwrap().unwrap();
        let notice = viewer.from_agent.recv().await.unwrap();
        assert!(matches!(notice.msg, Some(Msg::Notice(n)) if n.kind == NoticeKind::SessionSwitching as i32));

        // New agent connects -> receives KeyframeRequest automatically.
        let (service_end2, mut agent_end2) = tokio::io::duplex(16 * 1024);
        let task2 = tokio::spawn(serve_stream(service_end2, bridge.clone(), stop_rx));
        let mut agent_dec2 = Decoder::new();
        let kf2 = read_envelope(&mut agent_end2, &mut agent_dec2).await;
        assert!(matches!(kf2.msg, Some(Msg::KeyframeRequest(_))));

        let _ = stop_tx.send(true);
        task2.await.unwrap().unwrap();
    }
}
