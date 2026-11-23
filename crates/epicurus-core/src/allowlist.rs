//! Data-driven allowlist.
//!
//! An entry matches on a valid Authenticode signer *plus* an image path
//! pattern (optionally pinned to a hash), or on a SHA-256 alone. A process
//! name alone is never enough: malware can call itself `MsMpEng.exe`, but it
//! cannot carry Microsoft's signature from Microsoft's install directory.

use serde::{Deserialize, Serialize};

use crate::paths::EnvMap;
use crate::{Error, Result, glob};

/// Defaults shipped with Epicurus.
pub const DEFAULT_ALLOWLIST: &str = r#"
# Microsoft Defender Antivirus engine and its platform services.
[[entry]]
name = "Microsoft Defender Antivirus"
signers = ["Microsoft Windows Publisher", "Microsoft Windows", "Microsoft Corporation"]
path = '%PROGRAMDATA%\Microsoft\Windows Defender\Platform\*\*.exe'

[[entry]]
name = "Microsoft Defender Antivirus (inbox)"
signers = ["Microsoft Windows Publisher", "Microsoft Windows", "Microsoft Corporation"]
path = '%PROGRAMFILES%\Windows Defender\*.exe'

[[entry]]
name = "Microsoft Defender for Endpoint"
signers = ["Microsoft Windows Publisher", "Microsoft Windows", "Microsoft Corporation"]
path = '%PROGRAMFILES%\Windows Defender Advanced Threat Protection\**'

# Windows Search indexer and its filter hosts.
[[entry]]
name = "Windows Search indexer"
signers = ["Microsoft Windows"]
path = '%SYSTEMROOT%\System32\SearchIndexer.exe'

[[entry]]
name = "Windows Search protocol host"
signers = ["Microsoft Windows"]
path = '%SYSTEMROOT%\System32\SearchProtocolHost.exe'

[[entry]]
name = "Windows Search filter host"
signers = ["Microsoft Windows"]
path = '%SYSTEMROOT%\System32\SearchFilterHost.exe'

# Common backup agents.
[[entry]]
name = "Veeam Agent"
signers = ["Veeam Software Group GmbH"]
path = '%PROGRAMFILES%\Veeam\**'

[[entry]]
name = "Acronis Cyber Protect"
signers = ["Acronis International GmbH"]
path = '%PROGRAMFILES%\Acronis\**'

[[entry]]
name = "Acronis Cyber Protect (x86)"
signers = ["Acronis International GmbH"]
path = '%PROGRAMFILES(X86)%\Acronis\**'

[[entry]]
name = "Backblaze"
signers = ["Backblaze, Inc."]
path = '%PROGRAMFILES(X86)%\Backblaze\**'

[[entry]]
name = "Macrium Reflect"
signers = ["Paramount Software UK Ltd"]
path = '%PROGRAMFILES%\Macrium\**'

[[entry]]
name = "CrashPlan"
signers = ["Code42 Software, Inc.", "CrashPlan Group LLC"]
path = '%PROGRAMFILES%\Code42\**'

[[entry]]
name = "Carbonite"
signers = ["Carbonite, Inc.", "Carbonite, LLC"]
path = '%PROGRAMFILES%\Carbonite\**'
"#;

/// One allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// Display name.
    pub name: String,
    /// Accepted leaf signer subject names (exact, case-insensitive).
    #[serde(default)]
    pub signers: Vec<String>,
    /// Image path pattern (may use `%VAR%`, `*`, `**`, `?`).
    #[serde(default)]
    pub path: String,
    /// Optional SHA-256 pin.
    #[serde(default)]
    pub sha256: Option<String>,
}

impl AllowEntry {
    /// Validates that the entry cannot degrade to a name-only match.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.len() > 200 {
            return Err(Error::Config(
                "allowlist entry needs a name (max 200 chars)".into(),
            ));
        }
        if let Some(h) = &self.sha256
            && (h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(Error::Config(format!(
                "{}: sha256 must be 64 hex characters",
                self.name
            )));
        }
        let has_signer =
            !self.signers.is_empty() && self.signers.iter().all(|s| !s.trim().is_empty());
        let has_path = !self.path.trim().is_empty();
        if has_signer != has_path {
            return Err(Error::Config(format!(
                "{}: signers and path must be given together",
                self.name
            )));
        }
        if !has_signer && self.sha256.is_none() {
            return Err(Error::Config(format!(
                "{}: needs signers + path, or a sha256",
                self.name
            )));
        }
        if has_path {
            let p = self.path.trim();
            let rooted = p.starts_with('%')
                || (p.len() > 2 && p.as_bytes()[1] == b':')
                || p.starts_with(r"\\");
            if !rooted || !p.contains('\\') {
                return Err(Error::Config(format!(
                    "{}: path must be a full path pattern, not a bare process name",
                    self.name
                )));
            }
            if p == "**" || p.ends_with(":\\**") || p.ends_with(":\\*") {
                return Err(Error::Config(format!(
                    "{}: path pattern is too broad",
                    self.name
                )));
            }
        }
        Ok(())
    }
}

/// What the allowlist needs to know about a process.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    /// DOS image path.
    pub image_path: &'a str,
    /// True only for a valid, trusted Authenticode signature.
    pub signature_valid: bool,
    /// Leaf signer subject name.
    pub signer: Option<&'a str>,
    /// Image SHA-256.
    pub sha256: Option<&'a str>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    #[serde(default)]
    entry: Vec<AllowEntry>,
}

/// A set of entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    /// Entries.
    pub entries: Vec<AllowEntry>,
}

impl Allowlist {
    /// Parses TOML (`[[entry]]` tables), validating each entry.
    pub fn parse(text: &str) -> Result<Self> {
        let file: AllowFile = toml::from_str(text)?;
        for e in &file.entry {
            e.validate()?;
        }
        Ok(Self {
            entries: file.entry,
        })
    }

    /// Serializes to TOML.
    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(&AllowFile {
            entry: self.entries.clone(),
        })?)
    }

    /// The built-in defaults.
    pub fn defaults() -> Self {
        // The defaults are a compile-time constant covered by a unit test, so
        // parsing cannot fail at runtime; fall back to empty rather than panic.
        Self::parse(DEFAULT_ALLOWLIST).unwrap_or_default()
    }

    /// Returns the first entry matching `subject`.
    pub fn find(&self, subject: &Subject<'_>, env: &EnvMap) -> Option<&AllowEntry> {
        self.entries.iter().find(|e| entry_matches(e, subject, env))
    }
}

fn entry_matches(e: &AllowEntry, s: &Subject<'_>, env: &EnvMap) -> bool {
    let hash_ok = match (&e.sha256, s.sha256) {
        (Some(want), Some(have)) => want.eq_ignore_ascii_case(have),
        (Some(_), None) => false,
        (None, _) => true,
    };
    if !hash_ok {
        return false;
    }
    if e.signers.is_empty() {
        // Hash-only entry (validated to have a hash).
        return e.sha256.is_some();
    }
    if !s.signature_valid {
        return false;
    }
    let Some(signer) = s.signer else { return false };
    if !e
        .signers
        .iter()
        .any(|w| w.trim().eq_ignore_ascii_case(signer.trim()))
    {
        return false;
    }
    match env.expand(&e.path) {
        Ok(pattern) => glob::matches(&pattern, s.image_path),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> EnvMap {
        let mut e = EnvMap::new();
        e.set("PROGRAMDATA", r"C:\ProgramData");
        e.set("PROGRAMFILES", r"C:\Program Files");
        e.set("PROGRAMFILES(X86)", r"C:\Program Files (x86)");
        e.set("SYSTEMROOT", r"C:\Windows");
        e
    }

    const DEFENDER: &str =
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25010.11-0\MsMpEng.exe";

    #[test]
    fn defaults_parse_and_match_defender() {
        let a = Allowlist::defaults();
        assert!(a.entries.len() >= 10);
        let s = Subject {
            image_path: DEFENDER,
            signature_valid: true,
            signer: Some("Microsoft Windows Publisher"),
            sha256: None,
        };
        assert_eq!(
            a.find(&s, &env()).map(|e| e.name.as_str()),
            Some("Microsoft Defender Antivirus")
        );
    }

    #[test]
    fn name_alone_never_matches() {
        let a = Allowlist::defaults();
        // Right file name, wrong place.
        let s = Subject {
            image_path: r"C:\Users\x\AppData\Local\Temp\MsMpEng.exe",
            signature_valid: true,
            signer: Some("Microsoft Windows Publisher"),
            sha256: None,
        };
        assert!(a.find(&s, &env()).is_none());
        // Right place, unsigned (e.g. dropped by malware with admin rights).
        let s = Subject {
            image_path: DEFENDER,
            signature_valid: false,
            signer: Some("Microsoft Windows Publisher"),
            sha256: None,
        };
        assert!(a.find(&s, &env()).is_none());
        // Right place, valid signature by someone else.
        let s = Subject {
            image_path: DEFENDER,
            signature_valid: true,
            signer: Some("Evil Corp"),
            sha256: None,
        };
        assert!(a.find(&s, &env()).is_none());
    }

    #[test]
    fn hash_pin_and_hash_only_entries() {
        let h = "a".repeat(64);
        let a = Allowlist::parse(&format!(
            "[[entry]]\nname = \"pinned\"\nsigners = [\"Acme\"]\npath = 'C:\\Tools\\acme.exe'\nsha256 = \"{h}\"\n\n[[entry]]\nname = \"hash only\"\nsha256 = \"{}\"\n",
            "b".repeat(64)
        ))
        .unwrap();
        let mut s = Subject {
            image_path: r"C:\Tools\acme.exe",
            signature_valid: true,
            signer: Some("Acme"),
            sha256: Some(&h),
        };
        assert_eq!(a.find(&s, &env()).unwrap().name, "pinned");
        let other = "c".repeat(64);
        s.sha256 = Some(&other);
        assert!(a.find(&s, &env()).is_none());
        let b = "B".repeat(64);
        let s = Subject {
            image_path: r"C:\anywhere\x.exe",
            signature_valid: false,
            signer: None,
            sha256: Some(&b),
        };
        assert_eq!(a.find(&s, &env()).unwrap().name, "hash only");
    }

    #[test]
    fn validation_rejects_weak_entries() {
        let bad = [
            "[[entry]]\nname = \"n\"\npath = 'C:\\x.exe'\n",
            "[[entry]]\nname = \"n\"\nsigners = [\"A\"]\n",
            "[[entry]]\nname = \"n\"\nsigners = [\"A\"]\npath = 'chrome.exe'\n",
            "[[entry]]\nname = \"n\"\nsigners = [\"A\"]\npath = 'C:\\**'\n",
            "[[entry]]\nname = \"n\"\nsha256 = \"xyz\"\n",
            "[[entry]]\nname = \"\"\nsha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "[[entry]]\nname = \"n\"\n",
        ];
        for b in bad {
            assert!(Allowlist::parse(b).is_err(), "should reject: {b}");
        }
    }

    #[test]
    fn toml_roundtrip() {
        let a = Allowlist::defaults();
        assert_eq!(Allowlist::parse(&a.to_toml().unwrap()).unwrap(), a);
    }
}
