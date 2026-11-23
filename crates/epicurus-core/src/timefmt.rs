//! Time helpers shared by storage, reports and IPC.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// RFC 3339 / ISO 8601 rendering in UTC. Formatting a valid UTC timestamp
/// cannot fail; the fallback exists only to avoid a panic path.
pub fn rfc3339(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| t.unix_timestamp().to_string())
}

/// Parses RFC 3339.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

/// Converts a Windows FILETIME (100 ns ticks since 1601-01-01) to UTC.
pub fn from_filetime(ticks: u64) -> Option<OffsetDateTime> {
    const EPOCH_DIFF_SECS: i128 = 11_644_473_600;
    let nanos = i128::from(ticks) * 100 - EPOCH_DIFF_SECS * 1_000_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()
}

/// Converts UTC to a Windows FILETIME.
pub fn to_filetime(t: OffsetDateTime) -> u64 {
    const EPOCH_DIFF_SECS: i128 = 11_644_473_600;
    let ticks = (t.unix_timestamp_nanos() + EPOCH_DIFF_SECS * 1_000_000_000) / 100;
    u64::try_from(ticks).unwrap_or(0)
}

/// Serde helpers storing timestamps as RFC 3339 strings.
pub mod serde_rfc3339 {
    pub use time::serde::rfc3339::*;

    /// Optional variant.
    pub mod option {
        pub use time::serde::rfc3339::option::*;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_roundtrip() {
        let t = time::macros::datetime!(2026-11-23 10:00:00 UTC);
        let ft = to_filetime(t);
        assert_eq!(from_filetime(ft), Some(t));
        // 1970-01-01 is 116444736000000000 ticks.
        assert_eq!(
            to_filetime(OffsetDateTime::UNIX_EPOCH),
            116_444_736_000_000_000
        );
    }

    #[test]
    fn rfc3339_roundtrip() {
        let t = time::macros::datetime!(2026-01-02 03:04:05 UTC);
        let s = rfc3339(t);
        assert_eq!(s, "2026-01-02T03:04:05Z");
        assert_eq!(parse_rfc3339(&s), Some(t));
    }
}
