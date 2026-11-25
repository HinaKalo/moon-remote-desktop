//! Host-side limit on PIN guessing.
//!
//! An attempt is counted as failed *before* the PAKE runs and only cleared on success,
//! so concurrent attempts, crashes or dropped connections cannot be used to get free
//! guesses. After [`Policy::free_attempts`] consecutive failures the host refuses
//! attempts for an exponentially growing time. The state is persisted by the host
//! service so a restart does not reset it.

use serde::{Deserialize, Serialize};

/// Lockout tuning.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Consecutive failures allowed before the first lockout.
    pub free_attempts: u32,
    /// First lockout length in seconds; doubles with every further failure.
    pub base_secs: u64,
    /// Longest lockout in seconds.
    pub max_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self { free_attempts: 5, base_secs: 30, max_secs: 3600 }
    }
}

/// Persisted lockout state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockout {
    /// Failures since the last success, including attempts in flight.
    pub failures: u32,
    /// Unix seconds until which attempts are refused (0 = not locked).
    pub locked_until: u64,
}

/// Result of asking to start an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Run the PAKE. `remaining` is how many more failures are allowed after this one
    /// before a lockout starts.
    Allowed { remaining: u32 },
    /// Refuse; retry after this many seconds.
    Locked { retry_after: u64 },
}

impl Lockout {
    /// Seconds left in the current lockout.
    pub fn retry_after(&self, now: u64) -> u64 {
        self.locked_until.saturating_sub(now)
    }

    /// Admits or refuses an attempt. An admitted attempt is already counted as a
    /// failure; persist the state before running the PAKE, and call
    /// [`Lockout::succeeded`] if it authenticates.
    pub fn begin(&mut self, now: u64, policy: &Policy) -> Admission {
        if now < self.locked_until {
            return Admission::Locked { retry_after: self.locked_until - now };
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures >= policy.free_attempts {
            let extra = self.failures - policy.free_attempts;
            let secs = policy.base_secs.checked_shl(extra.min(32)).unwrap_or(u64::MAX).min(policy.max_secs);
            self.locked_until = now.saturating_add(secs);
        }
        Admission::Allowed { remaining: policy.free_attempts.saturating_sub(self.failures) }
    }

    /// Clears the counter after a successful authentication.
    pub fn succeeded(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_free_attempts_then_doubling_lockout() {
        let p = Policy::default();
        let mut l = Lockout::default();
        let mut now = 1_000;
        for expected_remaining in [4, 3, 2, 1] {
            assert_eq!(l.begin(now, &p), Admission::Allowed { remaining: expected_remaining });
        }
        // Fifth attempt still runs, but arms a 30 s lockout for the next one.
        assert_eq!(l.begin(now, &p), Admission::Allowed { remaining: 0 });
        assert_eq!(l.begin(now, &p), Admission::Locked { retry_after: 30 });
        now += 30;
        assert_eq!(l.begin(now, &p), Admission::Allowed { remaining: 0 });
        assert_eq!(l.retry_after(now), 60);
        now += 60;
        l.begin(now, &p);
        assert_eq!(l.retry_after(now), 120);
    }

    #[test]
    fn lockout_is_capped() {
        let p = Policy::default();
        let mut l = Lockout { failures: 200, locked_until: 0 };
        l.begin(10, &p);
        assert_eq!(l.retry_after(10), 3600);
    }

    #[test]
    fn success_resets() {
        let p = Policy::default();
        let mut l = Lockout::default();
        for _ in 0..4 {
            l.begin(0, &p);
        }
        l.succeeded();
        assert_eq!(l, Lockout::default());
        assert_eq!(l.begin(0, &p), Admission::Allowed { remaining: 4 });
    }

    #[test]
    fn abandoned_attempts_still_count() {
        // Begin without ever finishing (connection dropped mid-PAKE): it stays a failure.
        let p = Policy::default();
        let mut l = Lockout::default();
        for _ in 0..5 {
            l.begin(0, &p);
        }
        assert!(matches!(l.begin(0, &p), Admission::Locked { .. }));
    }

    #[test]
    fn state_round_trips_through_json() {
        let l = Lockout { failures: 7, locked_until: 123 };
        let s = serde_json::to_string(&l).unwrap();
        assert_eq!(serde_json::from_str::<Lockout>(&s).unwrap(), l);
    }
}
