//! Explainable scoring.
//!
//! Every point added or removed comes with a reason code and a sentence shown
//! in the dashboard and the report, so an analyst can see exactly why a hit
//! was rated the way it was.

use serde::{Deserialize, Serialize};

use crate::incident::SignatureStatus;

/// Severity bands.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// 0-19.
    #[default]
    Info,
    /// 20-39.
    Low,
    /// 40-59.
    Medium,
    /// 60-79.
    High,
    /// 80-100.
    Critical,
}

impl Severity {
    /// Band for a score.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Severity::Info,
            20..=39 => Severity::Low,
            40..=59 => Severity::Medium,
            60..=79 => Severity::High,
            _ => Severity::Critical,
        }
    }

    /// Lower-case label.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Every band, ascending.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One explained contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    /// Stable code (documented in docs/incident-schema.md).
    pub code: String,
    /// Points (negative lowers the score).
    pub points: i32,
    /// Human explanation.
    pub detail: String,
}

/// Every reason code [`score`] can emit (documented in docs/incident-schema.md).
pub const REASON_CODES: &[&str] = &[
    "decoy_touched",
    "multiple_decoys",
    "two_categories",
    "category_sweep",
    "read_data",
    "destructive",
    "unsigned",
    "bad_signature",
    "trusted_signature",
    "temp_or_downloads",
    "user_writable_dir",
    "new_image",
    "real_secrets_opened",
    "network",
    "script_parent",
    "unattributed",
];

/// Facts the score is computed from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScoreInput {
    /// Distinct decoys touched within the sweep window.
    pub decoys_touched: usize,
    /// Distinct decoy categories touched within the window.
    pub categories_touched: usize,
    /// Seconds between the first and the latest distinct-decoy touch.
    pub sweep_span_secs: f64,
    /// Sweep window configured.
    pub sweep_window_secs: f64,
    /// Data was read from a decoy (not just opened).
    pub read_data: bool,
    /// A decoy was deleted, renamed or modified.
    pub destructive: bool,
    /// Signature of the image.
    pub signature: SignatureStatus,
    /// Image lives in a user-writable directory (AppData, profile).
    pub user_writable: bool,
    /// Image lives in %TEMP% or Downloads specifically.
    pub temp_or_downloads: bool,
    /// Seconds since the image file was created.
    pub image_age_secs: Option<u64>,
    /// Other sensitive real-credential paths opened in the window.
    pub sensitive_paths: usize,
    /// Open network connections.
    pub network_connections: usize,
    /// Parent is a script host or LOLBin.
    pub suspicious_parent: bool,
    /// No process could be attributed (oplock break without ETW event).
    pub unattributed: bool,
}

/// Score result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Score {
    /// 0-100.
    pub value: u8,
    /// Band.
    pub severity: Severity,
    /// Contributions in the order applied.
    pub reasons: Vec<Reason>,
}

fn add(reasons: &mut Vec<Reason>, code: &str, points: i32, detail: impl Into<String>) {
    reasons.push(Reason {
        code: code.to_string(),
        points,
        detail: detail.into(),
    });
}

/// Computes the score.
pub fn score(i: &ScoreInput) -> Score {
    let mut r = Vec::new();
    add(
        &mut r,
        "decoy_touched",
        40,
        "Opened a decoy credential that no legitimate software uses",
    );
    if i.decoys_touched > 1 {
        let extra = ((i.decoys_touched - 1) as i32 * 8).min(24);
        add(
            &mut r,
            "multiple_decoys",
            extra,
            format!("Touched {} distinct decoys", i.decoys_touched),
        );
    }
    let sweep = i.categories_touched >= 3 && i.sweep_span_secs <= i.sweep_window_secs;
    if i.categories_touched == 2 {
        add(
            &mut r,
            "two_categories",
            15,
            "Touched decoys in two different categories",
        );
    }
    if i.read_data {
        add(&mut r, "read_data", 5, "Read data from a decoy");
    }
    if i.destructive {
        add(
            &mut r,
            "destructive",
            15,
            "Deleted, renamed or modified a decoy",
        );
    }
    match i.signature {
        SignatureStatus::Unsigned => add(&mut r, "unsigned", 15, "Image is not signed"),
        SignatureStatus::Invalid => add(
            &mut r,
            "bad_signature",
            20,
            "Image signature is invalid or untrusted",
        ),
        SignatureStatus::Valid => add(
            &mut r,
            "trusted_signature",
            -20,
            "Image carries a valid, trusted signature",
        ),
        SignatureStatus::Unknown => {}
    }
    if i.temp_or_downloads {
        add(
            &mut r,
            "temp_or_downloads",
            15,
            "Image runs from %TEMP% or Downloads",
        );
    } else if i.user_writable {
        add(
            &mut r,
            "user_writable_dir",
            10,
            "Image runs from a user-writable directory",
        );
    }
    if let Some(age) = i.image_age_secs
        && age < 86_400
    {
        add(
            &mut r,
            "new_image",
            10,
            "Image file was created less than 24 hours ago",
        );
    }
    if i.sensitive_paths > 0 {
        add(
            &mut r,
            "real_secrets_opened",
            10,
            format!("Also opened {} real credential store(s)", i.sensitive_paths),
        );
    }
    if i.network_connections > 0 {
        add(
            &mut r,
            "network",
            5,
            format!("Has {} open network connection(s)", i.network_connections),
        );
    }
    if i.suspicious_parent {
        add(
            &mut r,
            "script_parent",
            5,
            "Launched by a script host or LOLBin",
        );
    }
    if i.unattributed {
        add(
            &mut r,
            "unattributed",
            0,
            "Oplock break observed but no process could be attributed",
        );
    }

    let sum: i32 = r.iter().map(|x| x.points).sum();
    let mut value = sum.clamp(0, 100);
    if sweep {
        let floor = 90;
        if value < floor {
            add(
                &mut r,
                "category_sweep",
                floor - value,
                format!(
                    "Swept {} decoy categories within {:.1}s: near-certain stealer",
                    i.categories_touched, i.sweep_span_secs
                ),
            );
            value = floor;
        } else {
            add(
                &mut r,
                "category_sweep",
                0,
                format!("Swept {} decoy categories", i.categories_touched),
            );
        }
    }
    let value = value as u8;
    Score {
        value,
        severity: Severity::from_score(value),
        reasons: r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ScoreInput {
        ScoreInput {
            decoys_touched: 1,
            categories_touched: 1,
            sweep_window_secs: 10.0,
            ..ScoreInput::default()
        }
    }

    #[test]
    fn bands() {
        assert_eq!(Severity::from_score(0), Severity::Info);
        assert_eq!(Severity::from_score(19), Severity::Info);
        assert_eq!(Severity::from_score(20), Severity::Low);
        assert_eq!(Severity::from_score(59), Severity::Medium);
        assert_eq!(Severity::from_score(60), Severity::High);
        assert_eq!(Severity::from_score(80), Severity::Critical);
        assert_eq!(Severity::from_score(100), Severity::Critical);
    }

    #[test]
    fn signed_single_touch_is_low() {
        let s = score(&ScoreInput {
            signature: SignatureStatus::Valid,
            ..base()
        });
        assert_eq!(s.value, 20);
        assert_eq!(s.severity, Severity::Low);
    }

    #[test]
    fn unsigned_dropper_from_temp_is_high() {
        let s = score(&ScoreInput {
            signature: SignatureStatus::Unsigned,
            temp_or_downloads: true,
            image_age_secs: Some(60),
            ..base()
        });
        assert_eq!(s.value, 80);
        assert_eq!(s.severity, Severity::Critical);
    }

    #[test]
    fn multi_category_sweep_is_critical_even_when_signed() {
        let s = score(&ScoreInput {
            decoys_touched: 4,
            categories_touched: 3,
            sweep_span_secs: 2.0,
            signature: SignatureStatus::Valid,
            ..base()
        });
        assert!(s.value >= 90);
        assert_eq!(s.severity, Severity::Critical);
        assert!(s.reasons.iter().any(|r| r.code == "category_sweep"));
    }

    #[test]
    fn slow_crawl_across_categories_is_not_a_sweep() {
        let s = score(&ScoreInput {
            decoys_touched: 3,
            categories_touched: 3,
            sweep_span_secs: 120.0,
            signature: SignatureStatus::Valid,
            ..base()
        });
        assert!(!s.reasons.iter().any(|r| r.code == "category_sweep"));
        assert!(s.value < 60);
    }

    #[test]
    fn every_emitted_code_is_declared() {
        let inputs = [
            ScoreInput {
                decoys_touched: 5,
                categories_touched: 3,
                sweep_span_secs: 1.0,
                read_data: true,
                destructive: true,
                signature: SignatureStatus::Unsigned,
                temp_or_downloads: true,
                image_age_secs: Some(1),
                sensitive_paths: 1,
                network_connections: 1,
                suspicious_parent: true,
                unattributed: true,
                ..base()
            },
            ScoreInput {
                categories_touched: 2,
                signature: SignatureStatus::Invalid,
                user_writable: true,
                ..base()
            },
            ScoreInput {
                signature: SignatureStatus::Valid,
                ..base()
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for i in &inputs {
            for r in score(i).reasons {
                assert!(
                    REASON_CODES.contains(&r.code.as_str()),
                    "undeclared code {}",
                    r.code
                );
                seen.insert(r.code);
            }
        }
        assert_eq!(
            seen.len(),
            REASON_CODES.len(),
            "every declared code is reachable"
        );
    }

    #[test]
    fn reasons_sum_to_value_and_value_is_clamped() {
        let s = score(&ScoreInput {
            decoys_touched: 10,
            categories_touched: 2,
            read_data: true,
            destructive: true,
            signature: SignatureStatus::Invalid,
            temp_or_downloads: true,
            image_age_secs: Some(1),
            sensitive_paths: 3,
            network_connections: 2,
            suspicious_parent: true,
            ..base()
        });
        assert_eq!(s.value, 100);
        let sum: i32 = s.reasons.iter().map(|r| r.points).sum();
        assert!(sum >= 100);

        let s = score(&base());
        let sum: i32 = s.reasons.iter().map(|r| r.points).sum();
        assert_eq!(sum, i32::from(s.value));
    }
}
