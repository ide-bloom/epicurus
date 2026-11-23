//! `config.toml`: protection, sensors, containment policy, alert channels,
//! canaries, UI preferences and install facts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::catalog::Category;
use crate::generators::GENERATOR_NAMES;
use crate::protect::Protected;
use crate::scoring::Severity;
use crate::{Error, Result};

/// Current config schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Containment action for a severity band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Record only.
    Observe,
    /// Record and alert.
    Alert,
    /// Alert and suspend the process tree until the user decides.
    Suspend,
}

/// Which file sensor to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SensorMode {
    /// Kernel-File ETW, falling back to SACL auditing if ETW cannot start.
    #[default]
    Auto,
    /// Always use SACL auditing and Security event 4663.
    Audit,
}

/// Dashboard theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    /// Dark (default).
    #[default]
    Dark,
    /// Light.
    Light,
}

/// What to protect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Protection {
    /// Catalog profile.
    pub profile: String,
    /// Categories excluded from the profile.
    pub disabled_categories: Vec<Category>,
    /// Re-plant a decoy automatically after it is deleted or modified.
    pub auto_replant: bool,
}

impl Default for Protection {
    fn default() -> Self {
        Self {
            profile: "default".into(),
            disabled_categories: Vec::new(),
            auto_replant: true,
        }
    }
}

/// Sensor tuning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensorConfig {
    /// Real-time ETW session name.
    pub etw_session_name: String,
    /// File sensor mode.
    pub mode: SensorMode,
    /// Hold oplocks on decoys for early warning.
    pub oplock: bool,
    /// How long an oplock break waits for an ETW event naming the process.
    pub correlation_window_ms: u64,
    /// Window in which touches from one process aggregate into one incident.
    pub sweep_window_secs: u64,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            etw_session_name: "Epicurus-Sensor".into(),
            mode: SensorMode::Auto,
            oplock: true,
            correlation_window_ms: 3000,
            sweep_window_secs: 10,
        }
    }
}

/// Containment policy per severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Info band.
    pub info: PolicyAction,
    /// Low band.
    pub low: PolicyAction,
    /// Medium band.
    pub medium: PolicyAction,
    /// High band.
    pub high: PolicyAction,
    /// Critical band.
    pub critical: PolicyAction,
    /// Write a minidump of suspended processes. Off by default: dumps can be
    /// hundreds of megabytes and contain whatever the process had in memory,
    /// including secrets it already stole.
    pub minidump: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            info: PolicyAction::Observe,
            low: PolicyAction::Alert,
            medium: PolicyAction::Alert,
            high: PolicyAction::Suspend,
            critical: PolicyAction::Suspend,
            minidump: false,
        }
    }
}

impl PolicyConfig {
    /// The action for a severity.
    pub fn action_for(&self, s: Severity) -> PolicyAction {
        match s {
            Severity::Info => self.info,
            Severity::Low => self.low,
            Severity::Medium => self.medium,
            Severity::High => self.high,
            Severity::Critical => self.critical,
        }
    }
}

/// A webhook channel whose URL is stored encrypted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookChannel {
    /// Enabled.
    pub enabled: bool,
    /// DPAPI-protected URL.
    pub url: Protected,
}

/// ntfy channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NtfyChannel {
    /// Enabled.
    pub enabled: bool,
    /// Server base URL.
    pub server: String,
    /// DPAPI-protected topic (topics are bearer secrets on public servers).
    pub topic: Protected,
    /// DPAPI-protected access token (optional).
    pub token: Protected,
}

impl Default for NtfyChannel {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "https://ntfy.sh".into(),
            topic: Protected::default(),
            token: Protected::default(),
        }
    }
}

/// Generic JSON webhook with HMAC signature.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GenericChannel {
    /// Enabled.
    pub enabled: bool,
    /// DPAPI-protected URL.
    pub url: Protected,
    /// DPAPI-protected HMAC-SHA256 key.
    pub secret: Protected,
}

/// Alerting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AlertsConfig {
    /// Lowest severity that alerts at all.
    pub min_severity: Severity,
    /// Windows toast (shown by the tray agent).
    pub toast: bool,
    /// Windows Event Log.
    pub eventlog: bool,
    /// Suppress repeat alerts for the same image and severity within this window.
    pub dedupe_window_secs: u64,
    /// Per-channel rate limit.
    pub max_per_minute: u32,
    /// Discord.
    pub discord: WebhookChannel,
    /// Slack.
    pub slack: WebhookChannel,
    /// ntfy.
    pub ntfy: NtfyChannel,
    /// Generic JSON webhook.
    pub generic: GenericChannel,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Low,
            toast: true,
            eventlog: true,
            dedupe_window_secs: 600,
            max_per_minute: 10,
            discord: WebhookChannel::default(),
            slack: WebhookChannel::default(),
            ntfy: NtfyChannel::default(),
            generic: GenericChannel::default(),
        }
    }
}

/// UI preferences.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Theme.
    pub theme: Theme,
}

/// Facts recorded by `epicurus install`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InstallInfo {
    /// SID of the interactive user who installed Epicurus (pipe DACL, decoy owner).
    pub user_sid: String,
    /// That user's profile directory.
    pub profile_path: String,
    /// Roaming AppData if redirected.
    pub appdata: Option<String>,
    /// Local AppData if redirected.
    pub localappdata: Option<String>,
    /// Directory holding the installed epicurus.exe.
    pub install_dir: String,
}

/// The whole configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Schema version.
    pub schema_version: u32,
    /// Protection.
    pub protection: Protection,
    /// Sensors.
    pub sensor: SensorConfig,
    /// Containment.
    pub policy: PolicyConfig,
    /// Alerts.
    pub alerts: AlertsConfig,
    /// Live canary values, keyed by generator name (e.g. `aws_access_key_id`).
    pub canaries: BTreeMap<String, String>,
    /// UI.
    pub ui: UiConfig,
    /// Install facts.
    pub install: InstallInfo,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            protection: Protection::default(),
            sensor: SensorConfig::default(),
            policy: PolicyConfig::default(),
            alerts: AlertsConfig::default(),
            canaries: BTreeMap::new(),
            ui: UiConfig::default(),
            install: InstallInfo::default(),
        }
    }
}

impl Config {
    /// Parses and validates.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Loads from `path`; a missing file yields defaults.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::io(path, e)),
        }
    }

    /// Validates and writes atomically (temp file + rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let text = toml::to_string_pretty(self)?;
        write_atomic(path, text.as_bytes())
    }

    /// Checks every invariant the rest of the program relies on.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "unsupported schema_version {}",
                self.schema_version
            )));
        }
        let name = &self.sensor.etw_session_name;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::Config(
                "sensor.etw_session_name must be 1-64 characters of [A-Za-z0-9_-]".into(),
            ));
        }
        if !(100..=30_000).contains(&self.sensor.correlation_window_ms) {
            return Err(Error::Config(
                "sensor.correlation_window_ms must be 100..=30000".into(),
            ));
        }
        if !(1..=300).contains(&self.sensor.sweep_window_secs) {
            return Err(Error::Config(
                "sensor.sweep_window_secs must be 1..=300".into(),
            ));
        }
        if self.alerts.max_per_minute == 0 || self.alerts.max_per_minute > 600 {
            return Err(Error::Config(
                "alerts.max_per_minute must be 1..=600".into(),
            ));
        }
        if self.alerts.dedupe_window_secs > 86_400 {
            return Err(Error::Config(
                "alerts.dedupe_window_secs must be at most 86400".into(),
            ));
        }
        let server = self.alerts.ntfy.server.trim();
        if !server.starts_with("https://") && !server.starts_with("http://") {
            return Err(Error::Config(
                "alerts.ntfy.server must be an http(s) URL".into(),
            ));
        }
        for (k, v) in &self.canaries {
            if !GENERATOR_NAMES.contains(&k.as_str()) {
                return Err(Error::Config(format!("canaries: unknown generator {k:?}")));
            }
            if v.is_empty() || v.len() > 4096 || v.chars().any(|c| c.is_control() && c != '\n') {
                return Err(Error::Config(format!(
                    "canaries.{k}: value must be 1-4096 printable characters"
                )));
            }
        }
        Ok(())
    }

    /// Categories enabled under the current profile.
    pub fn enabled_categories(
        &self,
        catalog: &crate::catalog::Catalog,
    ) -> Result<std::collections::BTreeSet<Category>> {
        let mut cats = catalog.profile_categories(&self.protection.profile)?;
        for c in &self.protection.disabled_categories {
            cats.remove(c);
        }
        Ok(cats)
    }

    /// Profile variables for the protected user.
    pub fn env_map(&self) -> Option<crate::paths::EnvMap> {
        if self.install.profile_path.is_empty() {
            return None;
        }
        Some(crate::paths::EnvMap::for_profile(
            Path::new(&self.install.profile_path),
            self.install.appdata.as_deref().map(Path::new),
            self.install.localappdata.as_deref().map(Path::new),
        ))
    }
}

/// Writes a file atomically: write to a sibling temp file then rename over.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp: PathBuf = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| Error::io(&tmp, e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip_and_validate() {
        let c = Config::default();
        c.validate().unwrap();
        let text = toml::to_string_pretty(&c).unwrap();
        assert_eq!(Config::parse(&text).unwrap(), c);
        assert_eq!(
            c.policy.action_for(Severity::Critical),
            PolicyAction::Suspend
        );
        assert_eq!(c.policy.action_for(Severity::High), PolicyAction::Suspend);
        assert_eq!(c.policy.action_for(Severity::Info), PolicyAction::Observe);
        assert!(!c.policy.minidump);
    }

    #[test]
    fn partial_files_fill_defaults() {
        let c = Config::parse("[policy]\nhigh = \"alert\"\n[ui]\ntheme = \"light\"\n").unwrap();
        assert_eq!(c.policy.high, PolicyAction::Alert);
        assert_eq!(c.policy.critical, PolicyAction::Suspend);
        assert_eq!(c.ui.theme, Theme::Light);
    }

    #[test]
    fn rejects_invalid_values() {
        for bad in [
            "schema_version = 2",
            "[sensor]\netw_session_name = \"bad name\"",
            "[sensor]\ncorrelation_window_ms = 5",
            "[alerts]\nmax_per_minute = 0",
            "[canaries]\nnot_a_generator = \"x\"",
            "[canaries]\naws_access_key_id = \"\"",
            "[policy]\nhigh = \"nuke\"",
            "unknown_key = 1",
            "[alerts.ntfy]\nserver = \"ftp://x\"",
        ] {
            assert!(Config::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn canaries_parse() {
        let c = Config::parse(
            "[canaries]\naws_access_key_id = \"ABC\"\naws_secret_access_key = \"DEF\"\n",
        )
        .unwrap();
        assert_eq!(c.canaries.len(), 2);
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        assert_eq!(Config::load(&p).unwrap(), Config::default());
        let mut c = Config::default();
        c.protection.disabled_categories.push(Category::Wallet);
        c.save(&p).unwrap();
        assert_eq!(Config::load(&p).unwrap(), c);
    }
}
