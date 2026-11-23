//! Path handling: the data directory layout, `%VAR%` template expansion,
//! NT device path normalization and case-insensitive containment checks.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Layout of `%ProgramData%\Epicurus` (or an override used by tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// Uses an explicit root; tests and the integration harness point this at
    /// a temporary directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The production location, `%ProgramData%\Epicurus`.
    pub fn system() -> Self {
        Self::new(program_data().join("Epicurus"))
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// `config.toml`.
    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    /// User allowlist file.
    pub fn allowlist_file(&self) -> PathBuf {
        self.root.join("allowlist.toml")
    }
    /// SQLite database holding the manifest and incidents.
    pub fn database(&self) -> PathBuf {
        self.root.join("epicurus.db")
    }
    /// Rolling log directory.
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }
    /// Quarantine directory for neutralized images.
    pub fn quarantine(&self) -> PathBuf {
        self.root.join("quarantine")
    }
    /// User catalog overrides.
    pub fn catalog_d(&self) -> PathBuf {
        self.root.join("catalog.d")
    }
    /// Minidumps (only written when explicitly enabled).
    pub fn dumps(&self) -> PathBuf {
        self.root.join("dumps")
    }
    /// Exported reports written by the service on request.
    pub fn exports(&self) -> PathBuf {
        self.root.join("exports")
    }
}

/// `%ProgramData%`, falling back to the default location.
pub fn program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// Variables available to path templates. Keys are upper-cased.
///
/// The service runs as LocalSystem, so it cannot use its own environment to
/// find the protected user's profile. The map is built from the profile path
/// recorded at install time instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvMap {
    vars: BTreeMap<String, String>,
}

impl EnvMap {
    /// Empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds the standard profile variables from a profile root. Explicit
    /// roaming/local paths override the defaults when folder redirection is in
    /// use.
    pub fn for_profile(profile: &Path, appdata: Option<&Path>, local: Option<&Path>) -> Self {
        let mut map = Self::new();
        let p = profile.to_string_lossy().trim_end_matches('\\').to_string();
        map.set("USERPROFILE", &p);
        map.set(
            "APPDATA",
            &appdata
                .map(|a| a.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!(r"{p}\AppData\Roaming")),
        );
        map.set(
            "LOCALAPPDATA",
            &local
                .map(|a| a.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!(r"{p}\AppData\Local")),
        );
        map
    }

    /// Adds machine-wide variables used by the allowlist.
    pub fn with_system_vars(mut self) -> Self {
        for (key, default) in [
            ("SYSTEMROOT", r"C:\Windows"),
            ("WINDIR", r"C:\Windows"),
            ("PROGRAMDATA", r"C:\ProgramData"),
            ("PROGRAMFILES", r"C:\Program Files"),
            ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        ] {
            let value = std::env::var(key).unwrap_or_else(|_| default.to_string());
            self.set(key, &value);
        }
        self
    }

    /// Sets a variable (key is case-insensitive).
    pub fn set(&mut self, key: &str, value: &str) {
        self.vars
            .insert(key.to_ascii_uppercase(), value.to_string());
    }

    /// Looks a variable up (case-insensitive).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(&key.to_ascii_uppercase()).map(String::as_str)
    }

    /// Paths of the profile roots decoys may be planted under.
    pub fn allowed_roots(&self) -> Vec<PathBuf> {
        ["USERPROFILE", "APPDATA", "LOCALAPPDATA"]
            .iter()
            .filter_map(|k| self.get(k))
            .map(PathBuf::from)
            .collect()
    }

    /// Expands every `%NAME%` in `template`. Unknown variables are an error so
    /// a typo in a catalog override can never resolve to a relative path.
    pub fn expand(&self, template: &str) -> Result<String> {
        let mut out = String::with_capacity(template.len() + 32);
        let mut rest = template;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('%') else {
                return Err(Error::Template(format!(
                    "unterminated %VAR% in {template:?}"
                )));
            };
            let name = &after[..end];
            if name.is_empty() {
                out.push('%');
            } else {
                let value = self
                    .get(name)
                    .ok_or_else(|| Error::UnknownVar(name.to_string()))?;
                out.push_str(value);
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }
}

/// Canonical comparison key for a Windows path: backslashes, no `\\?\`
/// prefix, no trailing separator, lower-case. Windows paths are
/// case-insensitive for our purposes (NTFS per-directory case sensitivity is
/// not used in user profiles).
pub fn normalize_key(path: &str) -> String {
    let mut s = path.replace('/', "\\");
    for prefix in [r"\\?\UNC\", r"\??\UNC\"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = format!(r"\\{rest}");
        }
    }
    for prefix in [r"\\?\", r"\??\"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    while s.len() > 3 && s.ends_with('\\') {
        s.pop();
    }
    s.to_lowercase()
}

/// True when `path` equals `root` or lies beneath it, compared
/// case-insensitively on whole path components.
pub fn is_within(path: &Path, root: &Path) -> bool {
    let p = normalize_key(&path.to_string_lossy());
    let r = normalize_key(&root.to_string_lossy());
    if r.is_empty() {
        return false;
    }
    if p == r {
        return true;
    }
    let r_with_sep = if r.ends_with('\\') {
        r
    } else {
        format!("{r}\\")
    };
    p.starts_with(&r_with_sep)
}

/// True when `path` lies within any of `roots`.
pub fn is_within_any<'a>(path: &Path, roots: impl IntoIterator<Item = &'a PathBuf>) -> bool {
    roots.into_iter().any(|r| is_within(path, r))
}

/// Maps NT device paths (`\Device\HarddiskVolume3\Users\...`) to DOS paths
/// (`C:\Users\...`).
///
/// Kernel ETW reports file and image names in NT form. The table itself is
/// filled from `QueryDosDeviceW` by the sensor crate; normalization is kept
/// here as a pure function so it can be tested exhaustively.
#[derive(Debug, Clone, Default)]
pub struct DeviceMap {
    /// `(lower-cased device prefix, drive)` sorted longest prefix first.
    entries: Vec<(String, String)>,
}

impl DeviceMap {
    /// Builds a map from `(device, drive)` pairs such as
    /// `("\Device\HarddiskVolume3", "C:")`.
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut entries: Vec<(String, String)> = pairs
            .into_iter()
            .map(|(dev, drive)| {
                (
                    dev.trim_end_matches('\\').to_lowercase(),
                    drive.trim_end_matches('\\').to_string(),
                )
            })
            .filter(|(dev, _)| !dev.is_empty())
            .collect();
        entries.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
        Self { entries }
    }

    /// Number of mapped devices.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no devices are mapped.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Converts an NT path into a DOS path. Paths that are already DOS paths
    /// are returned in canonical form; unknown devices yield `None`.
    pub fn normalize(&self, raw: &str) -> Option<String> {
        let path = raw.trim_end_matches('\0');
        if path.is_empty() {
            return None;
        }
        // Already DOS-shaped: "C:\..." or with a \??\ / \\?\ prefix.
        let stripped = path
            .strip_prefix(r"\??\")
            .or_else(|| path.strip_prefix(r"\\?\"))
            .unwrap_or(path);
        if stripped.len() >= 2 && stripped.as_bytes()[1] == b':' {
            return Some(stripped.to_string());
        }
        if let Some(rest) = stripped.strip_prefix(r"UNC\") {
            return Some(format!(r"\\{rest}"));
        }
        let lower = path.to_lowercase();
        // Network redirector: \Device\Mup\server\share\...
        if let Some(rest) = lower.strip_prefix(r"\device\mup\") {
            let offset = path.len() - rest.len();
            return Some(format!(r"\\{}", &path[offset..]));
        }
        for (dev, drive) in &self.entries {
            if lower.starts_with(dev.as_str()) {
                let tail = &path[dev.len()..];
                if tail.is_empty() {
                    return Some(format!("{drive}\\"));
                }
                // Require a component boundary so HarddiskVolume1 never
                // matches HarddiskVolume10.
                if tail.starts_with('\\') {
                    return Some(format!("{drive}{tail}"));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> DeviceMap {
        DeviceMap::new([
            (r"\Device\HarddiskVolume1".into(), "D:".into()),
            (r"\Device\HarddiskVolume10".into(), "E:".into()),
            (r"\Device\HarddiskVolume3".into(), "C:".into()),
        ])
    }

    #[test]
    fn normalizes_volume_paths() {
        let m = map();
        assert_eq!(
            m.normalize(r"\Device\HarddiskVolume3\Users\a\.aws\credentials")
                .as_deref(),
            Some(r"C:\Users\a\.aws\credentials")
        );
        assert_eq!(
            m.normalize(r"\Device\HarddiskVolume10\x").as_deref(),
            Some(r"E:\x")
        );
        assert_eq!(
            m.normalize(r"\Device\HarddiskVolume1\x").as_deref(),
            Some(r"D:\x")
        );
    }

    #[test]
    fn volume_prefix_requires_boundary() {
        let m = DeviceMap::new([(r"\Device\HarddiskVolume1".into(), "D:".into())]);
        assert_eq!(m.normalize(r"\Device\HarddiskVolume12\x"), None);
    }

    #[test]
    fn device_match_is_case_insensitive_and_keeps_tail_case() {
        let m = map();
        assert_eq!(
            m.normalize(r"\DEVICE\harddiskvolume3\Users\Bob").as_deref(),
            Some(r"C:\Users\Bob")
        );
    }

    #[test]
    fn handles_dos_unc_and_mup_forms() {
        let m = map();
        assert_eq!(m.normalize(r"\??\C:\x\y").as_deref(), Some(r"C:\x\y"));
        assert_eq!(m.normalize(r"\\?\C:\x").as_deref(), Some(r"C:\x"));
        assert_eq!(m.normalize(r"C:\x").as_deref(), Some(r"C:\x"));
        assert_eq!(
            m.normalize(r"\Device\Mup\srv\share\f.txt").as_deref(),
            Some(r"\\srv\share\f.txt")
        );
        assert_eq!(
            m.normalize(r"\??\UNC\srv\s\f").as_deref(),
            Some(r"\\srv\s\f")
        );
        assert_eq!(m.normalize(r"\Device\Unknown\f"), None);
        assert_eq!(m.normalize(""), None);
    }

    #[test]
    fn root_device_maps_to_drive_root() {
        assert_eq!(
            map().normalize(r"\Device\HarddiskVolume3").as_deref(),
            Some(r"C:\")
        );
    }

    #[test]
    fn trailing_nul_is_ignored() {
        assert_eq!(
            map().normalize("\\Device\\HarddiskVolume3\\a\0").as_deref(),
            Some(r"C:\a")
        );
    }

    #[test]
    fn expands_env_templates() {
        let env = EnvMap::for_profile(Path::new(r"C:\Users\dev"), None, None);
        assert_eq!(
            env.expand(r"%USERPROFILE%\.aws\credentials").unwrap(),
            r"C:\Users\dev\.aws\credentials"
        );
        assert_eq!(
            env.expand(r"%localappdata%\x").unwrap(),
            r"C:\Users\dev\AppData\Local\x"
        );
        assert!(matches!(env.expand(r"%NOPE%\x"), Err(Error::UnknownVar(_))));
        assert!(env.expand(r"%USERPROFILE\x").is_err());
        assert_eq!(env.expand("100%%").unwrap(), "100%");
    }

    #[test]
    fn containment_is_component_wise() {
        let root = Path::new(r"C:\Users\dev\OneDrive");
        assert!(is_within(
            Path::new(r"c:\users\DEV\onedrive\docs\a.txt"),
            root
        ));
        assert!(is_within(Path::new(r"C:\Users\dev\OneDrive"), root));
        assert!(!is_within(
            Path::new(r"C:\Users\dev\OneDrive - Contoso\a"),
            root
        ));
        assert!(!is_within(Path::new(r"C:\Users\dev"), root));
        assert!(is_within(Path::new(r"\\?\C:\Users\dev\OneDrive\x"), root));
        assert!(is_within(Path::new("C:/Users/dev/OneDrive/x"), root));
    }

    #[test]
    fn normalize_key_strips_prefixes() {
        assert_eq!(normalize_key(r"\\?\C:\A\B\"), r"c:\a\b");
        assert_eq!(normalize_key(r"C:\"), r"c:\");
        assert_eq!(normalize_key(r"\\?\UNC\srv\share"), r"\\srv\share");
    }
}
