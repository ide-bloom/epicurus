//! The decoy catalog: decoys described as data.
//!
//! The default catalog (`decoys/catalog.toml`) is embedded at compile time.
//! Users extend or override it with TOML files in
//! `%ProgramData%\Epicurus\catalog.d\`; an override entry with the same `id`
//! replaces the built-in one, and `disabled = true` removes it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::generators::GeneratorSpec;
use crate::{Error, Result, template};

/// The catalog shipped with this build.
pub const EMBEDDED_CATALOG: &str = include_str!("../../../decoys/catalog.toml");

/// Current catalog schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Decoy categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// AI coding agents and assistants.
    AiAgent,
    /// MCP server configurations with embedded keys.
    Mcp,
    /// Cloud and developer credentials.
    Cloud,
    /// Browser credential stores.
    Browser,
    /// Cryptocurrency wallets.
    Wallet,
    /// Messaging session stores.
    Messaging,
    /// Password manager exports.
    PasswordManager,
}

impl Category {
    /// Every category, in display order.
    pub const ALL: [Category; 7] = [
        Category::AiAgent,
        Category::Mcp,
        Category::Cloud,
        Category::Browser,
        Category::Wallet,
        Category::Messaging,
        Category::PasswordManager,
    ];

    /// Stable identifier used in config and IPC.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::AiAgent => "ai_agent",
            Category::Mcp => "mcp",
            Category::Cloud => "cloud",
            Category::Browser => "browser",
            Category::Wallet => "wallet",
            Category::Messaging => "messaging",
            Category::PasswordManager => "password_manager",
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Category::AiAgent => "AI coding agents",
            Category::Mcp => "MCP server configs",
            Category::Cloud => "Cloud and developer credentials",
            Category::Browser => "Browser stores",
            Category::Wallet => "Crypto wallets",
            Category::Messaging => "Messaging sessions",
            Category::PasswordManager => "Password manager exports",
        }
    }

    /// Parses the stable identifier.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What to do when no acceptable target remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Try the next target in the list (the default).
    #[default]
    Alternate,
    /// Only ever use the first acceptable target; skip on any conflict.
    Skip,
}

/// Built-in SQLite layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqliteShape {
    /// Chromium `Login Data`.
    ChromiumLoginData,
    /// Chromium `Network\Cookies`.
    ChromiumCookies,
    /// VS Code / Cursor `state.vscdb` (`ItemTable`).
    VscodeState,
}

/// A key/value pair, both templated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyValue {
    /// Key template.
    pub key: String,
    /// Value template.
    pub value: String,
}

/// How a decoy's bytes are produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Content {
    /// A rendered text template.
    Text {
        /// Template body.
        template: String,
    },
    /// A SQLite database in a built-in shape. Each row is a map of templated
    /// columns understood by the shape.
    Sqlite {
        /// Layout.
        shape: SqliteShape,
        /// Rows.
        #[serde(default)]
        rows: Vec<BTreeMap<String, String>>,
    },
    /// A LevelDB directory (`CURRENT`, `LOG`, `MANIFEST-*`, `*.log`) whose
    /// write-ahead log holds the given entries. The target is a directory.
    Leveldb {
        /// Entries written to the log.
        entries: Vec<KeyValue>,
    },
    /// Opaque bytes: an optional magic header, an optional rendered payload,
    /// then random fill up to a size drawn from `size`.
    Binary {
        /// Hex-encoded magic header.
        #[serde(default)]
        magic: Option<String>,
        /// Optional template embedded after the header.
        #[serde(default)]
        payload: Option<String>,
        /// Inclusive size range in bytes.
        size: [u64; 2],
    },
}

/// Plausibility metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plausibility {
    /// Backdated modification age range in days.
    #[serde(default = "default_age")]
    pub age_days: [u32; 2],
    /// Set FILE_ATTRIBUTE_HIDDEN.
    #[serde(default)]
    pub hidden: bool,
    /// Set FILE_ATTRIBUTE_NOT_CONTENT_INDEXED so the search indexer leaves
    /// the decoy alone.
    #[serde(default = "default_true")]
    pub not_content_indexed: bool,
    /// Pad text decoys with trailing whitespace/comments up to this range.
    #[serde(default)]
    pub pad_to: Option<[u64; 2]>,
}

fn default_age() -> [u32; 2] {
    [60, 720]
}

fn default_true() -> bool {
    true
}

impl Default for Plausibility {
    fn default() -> Self {
        Self {
            age_days: default_age(),
            hidden: false,
            not_content_indexed: true,
            pad_to: None,
        }
    }
}

/// Fields and conditions shared by a group of decoys (e.g. a decoy browser
/// profile whose files must agree on the profile directory).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDef {
    /// Shared field generators.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    /// Plant the group only if one of these paths exists.
    #[serde(default)]
    pub require_any: Vec<String>,
    /// Skip the group entirely if any of these paths exists.
    #[serde(default)]
    pub skip_if_any: Vec<String>,
}

/// One decoy definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyDef {
    /// Unique id (`[a-z0-9-]+`).
    pub id: String,
    /// Category.
    pub category: Category,
    /// Optional group sharing fields with other decoys.
    #[serde(default)]
    pub group: Option<String>,
    /// What the decoy imitates.
    #[serde(default)]
    pub description: String,
    /// Candidate targets in order of preference. The first one is the real
    /// tool's location; the rest are plausible alternates.
    pub targets: Vec<String>,
    /// If any of these exists the real tool is installed: the primary target
    /// is never used and only alternates are considered.
    #[serde(default)]
    pub installed_if: Vec<String>,
    /// Plant only if one of these paths exists (e.g. the browser is installed).
    #[serde(default)]
    pub require_any: Vec<String>,
    /// Skip entirely if any of these exists (e.g. the real wallet is installed).
    #[serde(default)]
    pub skip_if_any: Vec<String>,
    /// Directories that must be created by Epicurus. A candidate target under
    /// one of these is rejected if the directory already exists and is not in
    /// the manifest, so a decoy browser profile or project folder is never
    /// mixed into a real one.
    #[serde(default)]
    pub fresh_dirs: Vec<String>,
    /// Conflict policy.
    #[serde(default)]
    pub conflict: ConflictPolicy,
    /// Content.
    pub content: Content,
    /// Field generators local to this decoy.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    /// Plausibility metadata.
    #[serde(default)]
    pub plausibility: Plausibility,
    /// Overrides may set this to remove a built-in decoy.
    #[serde(default)]
    pub disabled: bool,
}

impl DecoyDef {
    /// The group key: the explicit group, or the decoy's own id.
    pub fn group_key(&self) -> &str {
        self.group.as_deref().unwrap_or(&self.id)
    }
}

/// A catalog file as written on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogFile {
    /// Schema version (must equal [`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Named value sets for `pick:` generators.
    #[serde(default)]
    pub sets: BTreeMap<String, Vec<String>>,
    /// Shared template snippets.
    #[serde(default)]
    pub snippets: BTreeMap<String, String>,
    /// Profiles: name to list of categories (`"*"` means all).
    #[serde(default)]
    pub profiles: BTreeMap<String, Vec<String>>,
    /// Groups.
    #[serde(default)]
    pub groups: BTreeMap<String, GroupDef>,
    /// Decoys.
    #[serde(default, rename = "decoy")]
    pub decoys: Vec<DecoyDef>,
}

/// A merged, validated catalog.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    /// Value sets.
    pub sets: BTreeMap<String, Vec<String>>,
    /// Snippets.
    pub snippets: BTreeMap<String, String>,
    /// Profiles.
    pub profiles: BTreeMap<String, Vec<String>>,
    /// Groups.
    pub groups: BTreeMap<String, GroupDef>,
    /// Enabled decoys.
    pub decoys: Vec<DecoyDef>,
}

impl Catalog {
    /// Parses one catalog document.
    pub fn parse_file(text: &str) -> Result<CatalogFile> {
        let file: CatalogFile = toml::from_str(text)?;
        if file.schema_version != SCHEMA_VERSION {
            return Err(Error::Catalog(format!(
                "unsupported catalog schema_version {} (expected {SCHEMA_VERSION})",
                file.schema_version
            )));
        }
        Ok(file)
    }

    /// The embedded catalog alone.
    pub fn embedded() -> Result<Self> {
        Self::from_files([Self::parse_file(EMBEDDED_CATALOG)?])
    }

    /// The embedded catalog merged with every `*.toml` in `dir` (sorted by
    /// file name). A missing directory is not an error.
    pub fn load_with_overrides(dir: &Path) -> Result<Self> {
        let mut files = vec![Self::parse_file(EMBEDDED_CATALOG)?];
        if dir.is_dir() {
            let mut paths: Vec<_> = std::fs::read_dir(dir)
                .map_err(|e| Error::io(dir, e))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension()
                        .is_some_and(|x| x.eq_ignore_ascii_case("toml"))
                })
                .collect();
            paths.sort();
            for p in paths {
                let text = std::fs::read_to_string(&p).map_err(|e| Error::io(&p, e))?;
                let file = Self::parse_file(&text)
                    .map_err(|e| Error::Catalog(format!("{}: {e}", p.display())))?;
                files.push(file);
            }
        }
        Self::from_files(files)
    }

    /// Merges files in order (later wins) and validates the result.
    pub fn from_files(files: impl IntoIterator<Item = CatalogFile>) -> Result<Self> {
        let mut cat = Catalog::default();
        let mut decoys: Vec<DecoyDef> = Vec::new();
        for f in files {
            cat.sets.extend(f.sets);
            cat.snippets.extend(f.snippets);
            cat.profiles.extend(f.profiles);
            cat.groups.extend(f.groups);
            for d in f.decoys {
                if let Some(existing) = decoys.iter_mut().find(|e| e.id == d.id) {
                    *existing = d;
                } else {
                    decoys.push(d);
                }
            }
        }
        cat.decoys = decoys.into_iter().filter(|d| !d.disabled).collect();
        cat.validate()?;
        Ok(cat)
    }

    /// Looks up a decoy.
    pub fn decoy(&self, id: &str) -> Option<&DecoyDef> {
        self.decoys.iter().find(|d| d.id == id)
    }

    /// Categories selected by a profile name.
    pub fn profile_categories(&self, profile: &str) -> Result<BTreeSet<Category>> {
        let entries = self
            .profiles
            .get(profile)
            .ok_or_else(|| Error::Catalog(format!("unknown profile {profile:?}")))?;
        let mut out = BTreeSet::new();
        for e in entries {
            if e == "*" {
                out.extend(Category::ALL);
            } else {
                out.insert(Category::parse(e).ok_or_else(|| {
                    Error::Catalog(format!("profile {profile:?}: unknown category {e:?}"))
                })?);
            }
        }
        Ok(out)
    }

    fn validate(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        if !self.profiles.contains_key("default") {
            return Err(Error::Catalog(
                "catalog must define a \"default\" profile".into(),
            ));
        }
        for name in self.profiles.keys() {
            self.profile_categories(name)?;
        }
        for (gname, g) in &self.groups {
            for (f, spec) in &g.fields {
                GeneratorSpec::parse(spec)
                    .map_err(|e| Error::Catalog(format!("group {gname}: field {f}: {e}")))?;
            }
            for p in g.require_any.iter().chain(&g.skip_if_any) {
                validate_path_template(p)
                    .map_err(|e| Error::Catalog(format!("group {gname}: {e}")))?;
            }
        }
        for d in &self.decoys {
            let ctx = |msg: String| Error::Catalog(format!("decoy {}: {msg}", d.id));
            if d.id.is_empty()
                || !d
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            {
                return Err(ctx("id must match [a-z0-9-]+".into()));
            }
            if !ids.insert(d.id.clone()) {
                return Err(ctx("duplicate id".into()));
            }
            if d.targets.is_empty() {
                return Err(ctx("at least one target is required".into()));
            }
            let group = match &d.group {
                Some(g) => Some(
                    self.groups
                        .get(g)
                        .ok_or_else(|| ctx(format!("unknown group {g:?}")))?,
                ),
                None => None,
            };
            let mut known: BTreeSet<String> = d.fields.keys().cloned().collect();
            if let Some(g) = group {
                known.extend(g.fields.keys().cloned());
            }
            for (f, spec) in &d.fields {
                GeneratorSpec::parse(spec).map_err(|e| ctx(format!("field {f}: {e}")))?;
            }
            for t in d
                .targets
                .iter()
                .chain(&d.installed_if)
                .chain(&d.require_any)
                .chain(&d.skip_if_any)
                .chain(&d.fresh_dirs)
            {
                validate_path_template(t).map_err(|e| ctx(e.to_string()))?;
            }
            let mut templates: Vec<&str> = d
                .targets
                .iter()
                .chain(&d.fresh_dirs)
                .map(String::as_str)
                .collect();
            match &d.content {
                Content::Text { template } => templates.push(template),
                Content::Sqlite { rows, .. } => {
                    templates.extend(rows.iter().flat_map(|r| r.values().map(String::as_str)));
                }
                Content::Leveldb { entries } => {
                    if entries.is_empty() {
                        return Err(ctx("leveldb content needs at least one entry".into()));
                    }
                    for kv in entries {
                        templates.push(&kv.key);
                        templates.push(&kv.value);
                    }
                }
                Content::Binary {
                    magic,
                    payload,
                    size,
                } => {
                    if size[0] > size[1] || size[1] > 16 * 1024 * 1024 {
                        return Err(ctx(
                            "binary size range must be ordered and at most 16 MiB".into()
                        ));
                    }
                    if let Some(m) = magic {
                        hex::decode(m).map_err(|_| ctx("magic must be hex".into()))?;
                    }
                    if let Some(p) = payload {
                        templates.push(p);
                    }
                }
            }
            for t in templates {
                for field in template::referenced_fields(t) {
                    if !known.contains(&field) {
                        return Err(ctx(format!(
                            "template references undefined field {field:?}"
                        )));
                    }
                }
                check_snippets(t, &self.snippets).map_err(|e| ctx(e.to_string()))?;
            }
            let [lo, hi] = d.plausibility.age_days;
            if lo > hi || hi > 3650 {
                return Err(ctx("age_days must be ordered and at most 3650".into()));
            }
        }
        Ok(())
    }
}

fn check_snippets(t: &str, snippets: &BTreeMap<String, String>) -> Result<()> {
    let mut rest = t;
    while let Some(start) = rest.find("{{@") {
        let after = &rest[start + 3..];
        let end = after
            .find("}}")
            .ok_or_else(|| Error::Catalog("unterminated snippet".into()))?;
        let name = after[..end].trim();
        if !snippets.contains_key(name) {
            return Err(Error::Catalog(format!("unknown snippet {name:?}")));
        }
        rest = &after[end + 2..];
    }
    Ok(())
}

/// Path templates must be rooted in the user profile through a variable and
/// must not climb out of it with `..`, so an override can never point
/// Epicurus at system files.
pub fn validate_path_template(t: &str) -> Result<()> {
    let upper = t.to_ascii_uppercase();
    if !["%USERPROFILE%\\", "%APPDATA%\\", "%LOCALAPPDATA%\\"]
        .iter()
        .any(|p| upper.starts_with(p))
    {
        return Err(Error::Catalog(format!(
            "path {t:?} must start with %USERPROFILE%\\, %APPDATA%\\ or %LOCALAPPDATA%\\"
        )));
    }
    if t.split(['\\', '/']).any(|c| c == ".." || c == ".") {
        return Err(Error::Catalog(format!(
            "path {t:?} must not contain . or .. components"
        )));
    }
    if t.contains(':') {
        return Err(Error::Catalog(format!(
            "path {t:?} must not contain ':' (drive or stream)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_is_valid_and_covers_every_category() {
        let cat = Catalog::embedded().unwrap();
        for c in Category::ALL {
            assert!(
                cat.decoys.iter().any(|d| d.category == c),
                "no decoy for category {c}"
            );
        }
        assert!(cat.decoys.len() >= 30);
        assert_eq!(
            cat.profile_categories("default").unwrap().len(),
            Category::ALL.len()
        );
    }

    #[test]
    fn embedded_catalog_contains_no_token_literals() {
        // Every secret must be a placeholder. A crude but effective check:
        // no well-known provider prefix is followed directly by token body.
        let text = EMBEDDED_CATALOG;
        for prefix in [
            ["gh", "p_"],
            ["AK", "IA"],
            ["sk-", "ant-"],
            ["xo", "xb-"],
            ["sk", "_live_"],
        ] {
            let p = prefix.concat();
            assert!(!text.contains(&p), "catalog contains literal prefix {p}");
        }
    }

    #[test]
    fn overrides_replace_and_disable() {
        let base = Catalog::parse_file(EMBEDDED_CATALOG).unwrap();
        let first_id = base.decoys[0].id.clone();
        let second_id = base.decoys[1].id.clone();
        let over = format!(
            r#"
schema_version = 1
[[decoy]]
id = "{first_id}"
category = "cloud"
targets = ['%USERPROFILE%\custom\file.txt']
content = {{ kind = "text", template = "x" }}

[[decoy]]
id = "{second_id}"
category = "cloud"
targets = ['%USERPROFILE%\y']
content = {{ kind = "text", template = "y" }}
disabled = true
"#
        );
        let cat = Catalog::from_files([base, Catalog::parse_file(&over).unwrap()]).unwrap();
        assert_eq!(
            cat.decoy(&first_id).unwrap().targets[0],
            r"%USERPROFILE%\custom\file.txt"
        );
        assert!(cat.decoy(&second_id).is_none());
    }

    #[test]
    fn loads_overrides_from_catalog_d_in_name_order() {
        let dir = tempfile::tempdir().unwrap();
        let add = |name: &str, body: &str| std::fs::write(dir.path().join(name), body).unwrap();
        add(
            "10-add.toml",
            "schema_version = 1\n[[decoy]]\nid = \"team-token\"\ncategory = \"cloud\"\ntargets = ['%APPDATA%\\acme\\token.json']\nfields = { t = \"alnum:40\" }\ncontent = { kind = \"text\", template = \"{{t}}\" }\n",
        );
        // Later file wins: it disables the entry the first one added.
        add(
            "20-remove.toml",
            "schema_version = 1\n[[decoy]]\nid = \"aws-credentials\"\ncategory = \"cloud\"\ntargets = ['%USERPROFILE%\\x']\ncontent = { kind = \"text\", template = \"\" }\ndisabled = true\n",
        );
        add("notes.txt", "not toml, ignored");
        let cat = Catalog::load_with_overrides(dir.path()).unwrap();
        assert!(cat.decoy("team-token").is_some());
        assert!(cat.decoy("aws-credentials").is_none());

        // A broken override is reported with its file name.
        add(
            "30-broken.toml",
            "schema_version = 1\n[[decoy]]\nid = \"Bad Id\"\n",
        );
        let err = Catalog::load_with_overrides(dir.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("30-broken.toml"), "{err}");

        // A missing directory just means no overrides.
        assert!(Catalog::load_with_overrides(&dir.path().join("absent")).is_ok());
    }

    #[test]
    fn rejects_unsafe_targets() {
        assert!(validate_path_template(r"%USERPROFILE%\.aws\credentials").is_ok());
        assert!(validate_path_template(r"C:\Windows\System32\x").is_err());
        assert!(validate_path_template(r"%USERPROFILE%\..\Public\x").is_err());
        assert!(validate_path_template(r"%SYSTEMROOT%\x").is_err());
        assert!(validate_path_template(r"%USERPROFILE%\x:stream").is_err());
    }

    #[test]
    fn rejects_undefined_fields_and_bad_generators() {
        let bad_field = r#"
schema_version = 1
[profiles]
default = ["*"]
[[decoy]]
id = "a"
category = "cloud"
targets = ['%USERPROFILE%\a']
content = { kind = "text", template = "{{missing}}" }
"#;
        assert!(Catalog::from_files([Catalog::parse_file(bad_field).unwrap()]).is_err());
        let bad_gen = r#"
schema_version = 1
[profiles]
default = ["*"]
[[decoy]]
id = "a"
category = "cloud"
targets = ['%USERPROFILE%\a']
fields = { k = "nonsense" }
content = { kind = "text", template = "{{k}}" }
"#;
        assert!(Catalog::from_files([Catalog::parse_file(bad_gen).unwrap()]).is_err());
    }

    #[test]
    fn rejects_wrong_schema_version() {
        assert!(Catalog::parse_file("schema_version = 99").is_err());
    }
}
