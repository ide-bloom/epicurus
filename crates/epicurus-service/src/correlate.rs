//! Oplock-break correlation.
//!
//! An oplock break tells us *that* a decoy is being opened, with a precise
//! timestamp, but not *who*. The ETW Create event (or audit 4663) for the
//! same path names the process. Breaks wait in this queue for a matching
//! attributed event; breaks still unmatched after the correlation window are
//! reported as unattributed.

use std::time::{Duration, Instant};

use epicurus_core::paths::normalize_key;
use time::OffsetDateTime;

/// A break waiting for attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBreak {
    /// Precise time of the break.
    pub at: OffsetDateTime,
    /// Path as reported.
    pub path: String,
    key: String,
    received: Instant,
}

/// The queue.
#[derive(Debug, Default)]
pub struct BreakQueue {
    pending: Vec<PendingBreak>,
}

impl BreakQueue {
    /// Adds a break.
    pub fn push(&mut self, at: OffsetDateTime, path: &str, now: Instant) {
        self.pending.push(PendingBreak {
            at,
            path: path.to_string(),
            key: normalize_key(path),
            received: now,
        });
    }

    /// Removes and returns the earliest break on `path` within `window` of
    /// `event_at` (an attributed open). The returned break timestamp is the
    /// earliest evidence of the access.
    pub fn take_match(
        &mut self,
        path: &str,
        event_at: OffsetDateTime,
        window: Duration,
    ) -> Option<PendingBreak> {
        let key = normalize_key(path);
        let w = time::Duration::try_from(window).unwrap_or(time::Duration::seconds(3));
        let idx = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, b)| b.key == key && (b.at - event_at).abs() <= w)
            .min_by_key(|(_, b)| b.at)
            .map(|(i, _)| i)?;
        Some(self.pending.remove(idx))
    }

    /// Removes and returns breaks older than `window` (unattributed).
    pub fn expire(&mut self, now: Instant, window: Duration) -> Vec<PendingBreak> {
        let (old, keep): (Vec<_>, Vec<_>) = self
            .pending
            .drain(..)
            .partition(|b| now.duration_since(b.received) >= window);
        self.pending = keep;
        old
    }

    /// Number waiting.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// True if none are waiting.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_path_and_time() {
        let mut q = BreakQueue::default();
        let now = Instant::now();
        let t = OffsetDateTime::now_utc();
        q.push(t, r"C:\U\.aws\credentials", now);
        q.push(t, r"C:\U\.npmrc", now);
        assert!(
            q.take_match(
                r"c:\u\.AWS\credentials",
                t + time::Duration::milliseconds(40),
                Duration::from_secs(3)
            )
            .is_some()
        );
        assert_eq!(q.len(), 1);
        // Too far apart in time: no match.
        assert!(
            q.take_match(
                r"C:\U\.npmrc",
                t + time::Duration::seconds(30),
                Duration::from_secs(3)
            )
            .is_none()
        );
    }

    #[test]
    fn expires_unattributed_breaks() {
        let mut q = BreakQueue::default();
        let now = Instant::now();
        q.push(OffsetDateTime::now_utc(), r"C:\a", now);
        assert!(
            q.expire(now + Duration::from_millis(100), Duration::from_secs(3))
                .is_empty()
        );
        let gone = q.expire(now + Duration::from_secs(4), Duration::from_secs(3));
        assert_eq!(gone.len(), 1);
        assert!(q.is_empty());
    }
}
