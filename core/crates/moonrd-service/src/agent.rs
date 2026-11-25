//! Keeps exactly one session agent running in the active console session.
//!
//! The agent (capture, encode, input, clipboard) must run inside the user's session;
//! it is started as SYSTEM so it can also reach the secure desktop. On a session
//! switch the old agent is stopped and a new one started in the new session; a crashed
//! agent is restarted with exponential backoff. The logic is platform-independent and
//! driven by [`Supervisor::tick`] (called on a timer and on session-change events).

use std::io;
use std::time::{Duration, Instant};

/// A running agent.
pub trait AgentChild {
    fn session(&self) -> u32;
    fn exited(&self) -> bool;
    fn kill(&self);
}

/// How agents are found and started.
pub trait Platform {
    type Child: AgentChild;
    /// Session on the physical console, `None` while there is none (e.g. during a switch).
    fn active_session(&self) -> Option<u32>;
    fn spawn(&mut self, session: u32) -> io::Result<Self::Child>;
}

/// An agent that ran shorter than this counts as a failed start for backoff.
pub const STABLE_AFTER: Duration = Duration::from_secs(10);
const BACKOFF_BASE: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// What happened during a tick (for logging and status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Idle,
    Started { session: u32 },
    Stopped { session: u32, reason: StopReason },
    SpawnFailed { session: u32, error: String, retry_in: Duration },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The console moved to another session (or none).
    SessionChanged,
    /// The agent exited on its own.
    Exited,
}

struct Running<C> {
    child: C,
    started: Instant,
}

pub struct Supervisor<P: Platform> {
    platform: P,
    running: Option<Running<P::Child>>,
    failures: u32,
    next_try: Option<Instant>,
}

impl<P: Platform> Supervisor<P> {
    pub fn new(platform: P) -> Self {
        Self { platform, running: None, failures: 0, next_try: None }
    }

    /// Session the current agent runs in.
    pub fn agent_session(&self) -> Option<u32> {
        self.running.as_ref().map(|r| r.child.session())
    }

    /// Consecutive failed starts.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    fn backoff(&self) -> Duration {
        let exp = self.failures.saturating_sub(1).min(16);
        (BACKOFF_BASE * 2u32.pow(exp)).min(BACKOFF_MAX)
    }

    /// Reconciles the running agent with the active session. Returns at most one event.
    pub fn tick(&mut self, now: Instant) -> Event {
        let target = self.platform.active_session();

        if let Some(r) = &self.running {
            let session = r.child.session();
            if r.child.exited() {
                if now.duration_since(r.started) < STABLE_AFTER {
                    self.failures += 1;
                    self.next_try = Some(now + self.backoff());
                } else {
                    self.failures = 0;
                }
                self.running = None;
                return Event::Stopped { session, reason: StopReason::Exited };
            }
            if target != Some(session) {
                r.child.kill();
                self.running = None;
                // A deliberate switch is not a failure: start the new one immediately.
                self.next_try = None;
                return Event::Stopped { session, reason: StopReason::SessionChanged };
            }
            return Event::Idle;
        }

        let Some(session) = target else { return Event::Idle };
        if self.next_try.is_some_and(|t| now < t) {
            return Event::Idle;
        }
        match self.platform.spawn(session) {
            Ok(child) => {
                self.running = Some(Running { child, started: now });
                self.next_try = None;
                Event::Started { session }
            }
            Err(e) => {
                self.failures += 1;
                let retry_in = self.backoff();
                self.next_try = Some(now + retry_in);
                Event::SpawnFailed { session, error: e.to_string(), retry_in }
            }
        }
    }

    /// Stops the agent (service shutdown).
    pub fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            r.child.kill();
        }
    }
}

/// Windows platform: SYSTEM agent in the console session, in a kill-on-close job.
#[cfg(windows)]
pub mod windows_platform {
    use std::path::PathBuf;

    use super::*;
    use crate::win::{AgentProcess, Job, active_console_session, spawn_in_session};

    pub struct WinPlatform {
        pub exe: PathBuf,
        pub args: String,
        pub job: Job,
    }

    impl AgentChild for AgentProcess {
        fn session(&self) -> u32 {
            self.session
        }
        fn exited(&self) -> bool {
            self.exit_code().is_some()
        }
        fn kill(&self) {
            AgentProcess::kill(self)
        }
    }

    impl Platform for WinPlatform {
        type Child = AgentProcess;
        fn active_session(&self) -> Option<u32> {
            active_console_session()
        }
        fn spawn(&mut self, session: u32) -> io::Result<AgentProcess> {
            spawn_in_session(&self.exe, &self.args, session, &self.job)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;

    #[derive(Clone)]
    struct FakeChild {
        session: u32,
        exited: Rc<Cell<bool>>,
        killed: Rc<Cell<bool>>,
    }

    impl AgentChild for FakeChild {
        fn session(&self) -> u32 {
            self.session
        }
        fn exited(&self) -> bool {
            self.exited.get()
        }
        fn kill(&self) {
            self.killed.set(true);
            self.exited.set(true);
        }
    }

    #[derive(Default)]
    struct Fake {
        session: Rc<Cell<Option<u32>>>,
        fail: Rc<Cell<bool>>,
        spawned: Rc<RefCell<Vec<FakeChild>>>,
    }

    impl Platform for Fake {
        type Child = FakeChild;
        fn active_session(&self) -> Option<u32> {
            self.session.get()
        }
        fn spawn(&mut self, session: u32) -> io::Result<FakeChild> {
            if self.fail.get() {
                return Err(io::Error::other("boom"));
            }
            let c = FakeChild { session, exited: Rc::default(), killed: Rc::default() };
            self.spawned.borrow_mut().push(c.clone());
            Ok(c)
        }
    }

    type Setup = (Supervisor<Fake>, Rc<Cell<Option<u32>>>, Rc<Cell<bool>>, Rc<RefCell<Vec<FakeChild>>>);

    fn setup() -> Setup {
        let f = Fake::default();
        let (s, fail, spawned) = (f.session.clone(), f.fail.clone(), f.spawned.clone());
        (Supervisor::new(f), s, fail, spawned)
    }

    #[test]
    fn starts_in_console_session_and_follows_switches() {
        let (mut sup, session, _, spawned) = setup();
        let t = Instant::now();
        assert_eq!(sup.tick(t), Event::Idle, "no console session yet");
        session.set(Some(1));
        assert_eq!(sup.tick(t), Event::Started { session: 1 });
        assert_eq!(sup.tick(t), Event::Idle);
        session.set(Some(3)); // fast user switching
        assert_eq!(sup.tick(t), Event::Stopped { session: 1, reason: StopReason::SessionChanged });
        assert!(spawned.borrow()[0].killed.get());
        assert_eq!(sup.tick(t), Event::Started { session: 3 }, "new session starts without backoff");
        assert_eq!(sup.failures(), 0);
    }

    #[test]
    fn crash_loop_backs_off() {
        let (mut sup, session, _, spawned) = setup();
        session.set(Some(1));
        let mut t = Instant::now();
        assert_eq!(sup.tick(t), Event::Started { session: 1 });
        for expected in [1u64, 2, 4, 8] {
            spawned.borrow().last().unwrap().exited.set(true); // crashes immediately
            assert_eq!(sup.tick(t), Event::Stopped { session: 1, reason: StopReason::Exited });
            assert_eq!(sup.tick(t), Event::Idle, "must wait {expected}s");
            t += Duration::from_secs(expected);
            assert_eq!(sup.tick(t), Event::Started { session: 1 });
        }
        // A long-lived run resets the backoff.
        t += STABLE_AFTER;
        spawned.borrow().last().unwrap().exited.set(true);
        sup.tick(t);
        assert_eq!(sup.failures(), 0);
        assert_eq!(sup.tick(t), Event::Started { session: 1 });
    }

    #[test]
    fn spawn_failure_is_retried_with_cap() {
        let (mut sup, session, fail, _) = setup();
        session.set(Some(1));
        fail.set(true);
        let mut t = Instant::now();
        let mut last = Duration::ZERO;
        for _ in 0..10 {
            match sup.tick(t) {
                Event::SpawnFailed { retry_in, .. } => {
                    assert!(retry_in >= last && retry_in <= BACKOFF_MAX);
                    last = retry_in;
                    t += retry_in;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(last, BACKOFF_MAX);
        fail.set(false);
        assert_eq!(sup.tick(t), Event::Started { session: 1 });
    }

    #[test]
    fn stop_kills_agent() {
        let (mut sup, session, _, spawned) = setup();
        session.set(Some(1));
        sup.tick(Instant::now());
        sup.stop();
        assert!(spawned.borrow()[0].killed.get());
        assert_eq!(sup.agent_session(), None);
    }
}
