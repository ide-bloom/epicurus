//! Per-install seed and deterministic choices derived from it.
//!
//! Every plausibility decision (directory names, account names, file sizes,
//! backdated timestamps) comes from a keyed stream derived from a random
//! 32-byte seed generated at install time. Two machines therefore get
//! different decoys, so a stealer cannot skip them with a static blocklist,
//! while one machine gets the same layout every time it re-plants.
//!
//! The stream is HMAC-SHA256 in counter mode rather than a `rand` PRNG so the
//! layout does not change when the `rand` crate changes its algorithms.

use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;

/// The per-install seed.
#[derive(Clone, PartialEq, Eq)]
pub struct InstallSeed([u8; 32]);

impl std::fmt::Debug for InstallSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The seed decides the decoy layout; keep it out of logs.
        f.write_str("InstallSeed(..)")
    }
}

impl InstallSeed {
    /// Generates a fresh seed from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps existing seed bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses the hex form stored in the database.
    pub fn from_hex(s: &str) -> Option<Self> {
        let v = hex::decode(s.trim()).ok()?;
        let arr: [u8; 32] = v.try_into().ok()?;
        Some(Self(arr))
    }

    /// Hex form for storage.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// A deterministic stream scoped to `label` (typically a decoy group id),
    /// so adding a catalog entry never reshuffles the others.
    pub fn chooser(&self, label: &str) -> Chooser {
        Chooser {
            key: self.0,
            label: label.as_bytes().to_vec(),
            counter: 0,
        }
    }
}

/// Deterministic choice stream.
#[derive(Clone)]
pub struct Chooser {
    key: [u8; 32],
    label: Vec<u8>,
    counter: u64,
}

impl Chooser {
    /// Next 64 pseudo-random bits.
    pub fn next_u64(&mut self) -> u64 {
        // HMAC accepts keys of any length, so construction cannot fail; fall
        // back to a counter-only value rather than panicking regardless.
        let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key) else {
            self.counter = self.counter.wrapping_add(1);
            return self.counter;
        };
        mac.update(&self.label);
        mac.update(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        let out = mac.finalize().into_bytes();
        let mut b = [0u8; 8];
        b.copy_from_slice(&out[..8]);
        u64::from_le_bytes(b)
    }

    /// Uniform value in `lo..=hi` (inclusive). Returns `lo` if the range is
    /// empty or inverted.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        let span = hi - lo + 1;
        // Rejection sampling avoids modulo bias.
        let zone = u64::MAX - (u64::MAX % span);
        loop {
            let v = self.next_u64();
            if v < zone {
                return lo + v % span;
            }
        }
    }

    /// Picks one element; `None` for an empty slice.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let idx = self.range(0, items.len() as u64 - 1) as usize;
        items.get(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_label_is_deterministic() {
        let seed = InstallSeed::from_bytes([7; 32]);
        let a: Vec<u64> = (0..5)
            .map(|_| 0)
            .scan(seed.chooser("x"), |c, _| Some(c.next_u64()))
            .collect();
        let b: Vec<u64> = (0..5)
            .map(|_| 0)
            .scan(seed.chooser("x"), |c, _| Some(c.next_u64()))
            .collect();
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_or_labels_diverge() {
        let s1 = InstallSeed::from_bytes([1; 32]);
        let s2 = InstallSeed::from_bytes([2; 32]);
        assert_ne!(s1.chooser("x").next_u64(), s2.chooser("x").next_u64());
        assert_ne!(s1.chooser("x").next_u64(), s1.chooser("y").next_u64());
    }

    #[test]
    fn range_stays_in_bounds() {
        let mut c = InstallSeed::generate().chooser("r");
        for _ in 0..1000 {
            let v = c.range(10, 20);
            assert!((10..=20).contains(&v));
        }
        assert_eq!(c.range(5, 5), 5);
        assert_eq!(c.range(9, 3), 9);
    }

    #[test]
    fn hex_roundtrip() {
        let s = InstallSeed::generate();
        assert_eq!(InstallSeed::from_hex(&s.to_hex()), Some(s));
        assert!(InstallSeed::from_hex("abcd").is_none());
    }
}
