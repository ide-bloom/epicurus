//! Planting plans: which decoy goes where, and why others are skipped.
//!
//! Planning is pure with respect to the filesystem (all queries go through
//! [`FsProbe`]) so every safety rule is unit-tested:
//!
//! * a target that already exists is never chosen unless Epicurus planted it;
//! * if the real tool is installed (`installed_if`), its real location is
//!   never used, only alternates;
//! * targets inside cloud-synced folders or git working trees are rejected;
//! * targets under a `fresh_dirs` directory are rejected if that directory
//!   already exists and is not Epicurus's own;
//! * targets must resolve inside the protected user's profile.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use time::OffsetDateTime;

use crate::catalog::{Catalog, Category, Content, DecoyDef};
use crate::environment::{FsProbe, SyncProvider};
use crate::generators::{Entropy, GenContext, Generated, GeneratorSpec};
use crate::manifest::Manifest;
use crate::paths::{EnvMap, is_within, is_within_any};
use crate::seed::InstallSeed;
use crate::template::{RenderScope, render};
use crate::{Error, Result, leveldb, shapes};

/// Options for a planning run.
#[derive(Debug, Clone)]
pub struct PlanOptions {
    /// Categories to plant.
    pub categories: BTreeSet<Category>,
    /// User canary values keyed by generator name.
    pub canaries: BTreeMap<String, String>,
    /// Reference time.
    pub now: OffsetDateTime,
}

/// File attributes to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Attributes {
    /// FILE_ATTRIBUTE_HIDDEN.
    pub hidden: bool,
    /// FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.
    pub not_content_indexed: bool,
}

/// One file to write.
#[derive(Debug, Clone, Serialize)]
pub struct PlannedFile {
    /// Absolute path.
    pub path: PathBuf,
    /// Content (omitted from serialized dry-run output).
    #[serde(skip)]
    pub bytes: Vec<u8>,
    /// Size of `bytes`.
    pub size: u64,
    /// Backdated modification time.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub modified: OffsetDateTime,
    /// Attributes.
    pub attributes: Attributes,
}

/// One decoy to plant.
#[derive(Debug, Clone, Serialize)]
pub struct PlannedDecoy {
    /// Catalog id.
    pub decoy_id: String,
    /// Category.
    pub category: Category,
    /// Chosen target.
    pub target: PathBuf,
    /// Files to write (files already planted earlier are not repeated).
    pub files: Vec<PlannedFile>,
    /// Contains canary values.
    pub canary: bool,
    /// Index of the chosen candidate (0 = the real tool's location).
    pub candidate_index: usize,
}

/// Why a candidate target was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejection {
    /// The real tool is installed, so its real location is off limits.
    RealToolLocation,
    /// A file already exists at the path and Epicurus did not create it.
    Exists {
        /// The existing path.
        path: PathBuf,
    },
    /// The path is inside a cloud-synced folder.
    Synced {
        /// Provider.
        provider: SyncProvider,
    },
    /// The path is inside a git working tree.
    GitTree {
        /// Repository root.
        root: PathBuf,
    },
    /// A `fresh_dirs` directory already exists and is not Epicurus's own.
    NotFresh {
        /// The directory.
        dir: PathBuf,
    },
    /// The path resolves outside the protected profile.
    OutsideProfile,
}

/// Why a decoy was skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum SkipReason {
    /// Category not selected.
    CategoryDisabled,
    /// None of the `require_any` paths exists (e.g. browser not installed).
    RequirementMissing,
    /// A `skip_if_any` path exists (e.g. the real wallet is installed).
    RealInstalled {
        /// The path found.
        path: PathBuf,
    },
    /// Every file of the decoy is already planted.
    AlreadyPlanted,
    /// Every candidate was rejected.
    NoAcceptableTarget {
        /// Per-candidate rejections.
        rejections: Vec<(PathBuf, Rejection)>,
    },
}

/// A skipped decoy.
#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    /// Catalog id.
    pub decoy_id: String,
    /// Category.
    pub category: Category,
    /// Reason.
    #[serde(flatten)]
    pub reason: SkipReason,
}

/// The full plan.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Plan {
    /// Decoys to plant.
    pub planned: Vec<PlannedDecoy>,
    /// Decoys skipped.
    pub skipped: Vec<Skipped>,
}

/// A chosen `(candidate index, path)`, or every candidate with its rejection.
type TargetChoice = std::result::Result<(usize, PathBuf), Vec<(PathBuf, Rejection)>>;

/// Everything the planner needs.
pub struct Planner<'a> {
    /// Catalog.
    pub catalog: &'a Catalog,
    /// Profile variables.
    pub env: &'a EnvMap,
    /// Install seed.
    pub seed: &'a InstallSeed,
    /// Filesystem queries.
    pub fs: &'a dyn FsProbe,
    /// Current manifest.
    pub manifest: &'a Manifest,
}

impl Planner<'_> {
    /// Builds a plan. `entropy` supplies secret material.
    pub fn plan(&self, opts: &PlanOptions, entropy: &mut dyn Entropy) -> Result<Plan> {
        let mut plan = Plan::default();
        let mut group_fields: BTreeMap<String, BTreeMap<String, Generated>> = BTreeMap::new();

        for decoy in &self.catalog.decoys {
            let skip = |reason| Skipped {
                decoy_id: decoy.id.clone(),
                category: decoy.category,
                reason,
            };
            if !opts.categories.contains(&decoy.category) {
                plan.skipped.push(skip(SkipReason::CategoryDisabled));
                continue;
            }
            let group = decoy
                .group
                .as_ref()
                .and_then(|g| self.catalog.groups.get(g));
            let require: Vec<&String> = group
                .map(|g| g.require_any.iter().collect())
                .unwrap_or_default();
            if !self.any_real(&require)?
                || !self.any_real(&decoy.require_any.iter().collect::<Vec<_>>())?
            {
                plan.skipped.push(skip(SkipReason::RequirementMissing));
                continue;
            }
            let skip_paths: Vec<&String> = group
                .map(|g| g.skip_if_any.iter().collect::<Vec<_>>())
                .unwrap_or_default()
                .into_iter()
                .chain(&decoy.skip_if_any)
                .collect();
            if let Some(path) = self.first_real(&skip_paths)? {
                plan.skipped.push(skip(SkipReason::RealInstalled { path }));
                continue;
            }

            // Fields: group-level values are generated once and shared.
            let gkey = decoy.group_key().to_string();
            if !group_fields.contains_key(&gkey) {
                let defs = group.map(|g| g.fields.clone()).unwrap_or_default();
                let values = self.generate_fields(&gkey, &defs, opts, entropy)?;
                group_fields.insert(gkey.clone(), values);
            }
            let mut fields = group_fields.get(&gkey).cloned().unwrap_or_default();
            fields.extend(self.generate_fields(&decoy.id, &decoy.fields, opts, entropy)?);
            let scope = RenderScope {
                fields: &fields,
                snippets: &self.catalog.snippets,
            };

            match self.choose_target(decoy, &scope)? {
                Err(rejections) => {
                    plan.skipped
                        .push(skip(SkipReason::NoAcceptableTarget { rejections }));
                }
                Ok((idx, target)) => {
                    let files = self.render_files(decoy, &target, &scope, opts, entropy)?;
                    let pending: Vec<PlannedFile> = files
                        .into_iter()
                        .filter(|f| !self.manifest.owns(&f.path) || !self.fs.exists(&f.path))
                        .collect();
                    if pending.is_empty() {
                        plan.skipped.push(skip(SkipReason::AlreadyPlanted));
                        continue;
                    }
                    plan.planned.push(PlannedDecoy {
                        decoy_id: decoy.id.clone(),
                        category: decoy.category,
                        target,
                        files: pending,
                        canary: fields.values().any(|g| g.canary),
                        candidate_index: idx,
                    });
                }
            }
        }
        Ok(plan)
    }

    fn generate_fields(
        &self,
        label: &str,
        defs: &BTreeMap<String, String>,
        opts: &PlanOptions,
        entropy: &mut dyn Entropy,
    ) -> Result<BTreeMap<String, Generated>> {
        let mut chooser = self.seed.chooser(label);
        let mut out = BTreeMap::new();
        for (name, spec) in defs {
            // Each field gets its own sub-stream so reordering fields in the
            // catalog does not reshuffle the others.
            let mut field_chooser = self.seed.chooser(&format!("{label}/{name}"));
            let spec = GeneratorSpec::parse(spec)?;
            let mut ctx = GenContext {
                entropy,
                chooser: if spec.is_deterministic() {
                    &mut field_chooser
                } else {
                    &mut chooser
                },
                sets: &self.catalog.sets,
                canaries: &opts.canaries,
                now: opts.now,
            };
            out.insert(name.clone(), spec.generate(&mut ctx)?);
        }
        Ok(out)
    }

    fn resolve(&self, template: &str, scope: &RenderScope<'_>) -> Result<PathBuf> {
        let rendered = render(template, scope)?;
        Ok(PathBuf::from(self.env.expand(&rendered)?))
    }

    /// A path counts as "real" if it exists and Epicurus did not create it.
    fn is_real(&self, path: &Path) -> bool {
        self.fs.exists(path) && !self.manifest.owns(path)
    }

    fn first_real(&self, templates: &[&String]) -> Result<Option<PathBuf>> {
        for t in templates {
            let p = PathBuf::from(self.env.expand(t)?);
            if self.is_real(&p) {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    fn any_real(&self, templates: &[&String]) -> Result<bool> {
        if templates.is_empty() {
            return Ok(true);
        }
        Ok(self.first_real(templates)?.is_some())
    }

    fn choose_target(&self, decoy: &DecoyDef, scope: &RenderScope<'_>) -> Result<TargetChoice> {
        // A decoy planted earlier keeps its target.
        if let Some(existing) = self.manifest.for_decoy(&decoy.id).next() {
            let idx = decoy
                .targets
                .iter()
                .position(|t| {
                    self.resolve(t, scope)
                        .map(|p| {
                            crate::paths::normalize_key(&p.to_string_lossy())
                                == crate::paths::normalize_key(&existing.target.to_string_lossy())
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(0);
            return Ok(Ok((idx, existing.target.clone())));
        }

        let installed = self
            .first_real(&decoy.installed_if.iter().collect::<Vec<_>>())?
            .is_some();
        let fresh: Vec<PathBuf> = decoy
            .fresh_dirs
            .iter()
            .map(|t| self.resolve(t, scope))
            .collect::<Result<_>>()?;
        let roots = self.env.allowed_roots();
        let mut rejections = Vec::new();

        for (idx, t) in decoy.targets.iter().enumerate() {
            let path = self.resolve(t, scope)?;
            let rejection = if idx == 0 && installed {
                Some(Rejection::RealToolLocation)
            } else if !is_within_any(&path, &roots) {
                Some(Rejection::OutsideProfile)
            } else if let Some(root) = self.fs.synced_root(&path) {
                Some(Rejection::Synced {
                    provider: root.provider,
                })
            } else if let Some(root) = self.fs.git_root(&path) {
                Some(Rejection::GitTree { root })
            } else if let Some(dir) = fresh
                .iter()
                .find(|d| is_within(&path, d) && self.is_real(d))
            {
                Some(Rejection::NotFresh { dir: dir.clone() })
            } else {
                self.conflict_in(decoy, &path)
                    .map(|p| Rejection::Exists { path: p })
            };
            match rejection {
                None => return Ok(Ok((idx, path))),
                Some(r) => {
                    let stop = decoy.conflict == crate::catalog::ConflictPolicy::Skip
                        && !matches!(r, Rejection::RealToolLocation);
                    rejections.push((path, r));
                    if stop {
                        break;
                    }
                }
            }
        }
        Ok(Err(rejections))
    }

    /// First pre-existing, foreign path among the files this decoy would write.
    fn conflict_in(&self, decoy: &DecoyDef, target: &Path) -> Option<PathBuf> {
        let names: Vec<PathBuf> = match &decoy.content {
            Content::Leveldb { .. } => {
                if self.is_real(target) {
                    return Some(target.to_path_buf());
                }
                Vec::new()
            }
            _ => vec![target.to_path_buf()],
        };
        names.into_iter().find(|p| self.is_real(p))
    }

    fn render_files(
        &self,
        decoy: &DecoyDef,
        target: &Path,
        scope: &RenderScope<'_>,
        opts: &PlanOptions,
        entropy: &mut dyn Entropy,
    ) -> Result<Vec<PlannedFile>> {
        let mut chooser = self.seed.chooser(&format!("{}/plausibility", decoy.id));
        let [lo, hi] = decoy.plausibility.age_days;
        let age_secs = chooser.range(u64::from(lo) * 86_400, u64::from(hi) * 86_400 + 86_399);
        let modified = opts.now - time::Duration::seconds(age_secs as i64);
        let attributes = Attributes {
            hidden: decoy.plausibility.hidden,
            not_content_indexed: decoy.plausibility.not_content_indexed,
        };
        let file = |path: PathBuf, bytes: Vec<u8>| PlannedFile {
            size: bytes.len() as u64,
            path,
            bytes,
            modified,
            attributes,
        };

        Ok(match &decoy.content {
            Content::Text { template } => {
                let mut text = render(template, scope)?;
                if let Some([plo, phi]) = decoy.plausibility.pad_to {
                    let want = chooser.range(plo, phi) as usize;
                    while text.len() < want {
                        text.push('\n');
                    }
                }
                vec![file(target.to_path_buf(), text.into_bytes())]
            }
            Content::Sqlite { shape, rows } => {
                let rendered: Vec<BTreeMap<String, String>> = rows
                    .iter()
                    .map(|r| {
                        r.iter()
                            .map(|(k, v)| Ok((k.clone(), render(v, scope)?)))
                            .collect::<Result<BTreeMap<_, _>>>()
                    })
                    .collect::<Result<_>>()?;
                let bytes = shapes::build(*shape, &rendered, entropy, modified)?;
                vec![file(target.to_path_buf(), bytes)]
            }
            Content::Leveldb { entries } => {
                let kv: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|e| {
                        Ok((
                            render(&e.key, scope)?.into_bytes(),
                            render(&e.value, scope)?.into_bytes(),
                        ))
                    })
                    .collect::<Result<_>>()?;
                let stamp = modified
                    .format(time::macros::format_description!(
                        "[year]/[month]/[day]-[hour]:[minute]:[second].[subsecond digits:6]"
                    ))
                    .map_err(|e| Error::Template(e.to_string()))?;
                leveldb::directory(&kv, &stamp)
                    .into_iter()
                    .map(|(name, bytes)| file(target.join(name), bytes))
                    .collect()
            }
            Content::Binary {
                magic,
                payload,
                size,
            } => {
                let mut bytes = match magic {
                    Some(m) => hex::decode(m).map_err(|_| Error::Catalog("bad magic".into()))?,
                    None => Vec::new(),
                };
                if let Some(p) = payload {
                    bytes.extend(render(p, scope)?.into_bytes());
                }
                let want = chooser.range(size[0], size[1]) as usize;
                if bytes.len() < want {
                    let mut fill = vec![0u8; want - bytes.len()];
                    entropy.fill(&mut fill);
                    bytes.extend(fill);
                }
                vec![file(target.to_path_buf(), bytes)]
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::{RealFs, SyncedRoot};
    use crate::manifest::ManifestEntry;

    struct Fixture {
        dir: tempfile::TempDir,
        env: EnvMap,
        catalog: Catalog,
        seed: InstallSeed,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        Fixture {
            env: EnvMap::for_profile(&home, None, None),
            catalog: Catalog::embedded().unwrap(),
            seed: InstallSeed::from_bytes([3; 32]),
            dir,
        }
    }

    fn opts() -> PlanOptions {
        PlanOptions {
            categories: Category::ALL.into_iter().collect(),
            canaries: BTreeMap::new(),
            now: OffsetDateTime::now_utc(),
        }
    }

    fn plan_with(f: &Fixture, fs: &RealFs, manifest: &Manifest) -> Plan {
        Planner {
            catalog: &f.catalog,
            env: &f.env,
            seed: &f.seed,
            fs,
            manifest,
        }
        .plan(&opts(), &mut rand::rng())
        .unwrap()
    }

    fn home(f: &Fixture) -> PathBuf {
        PathBuf::from(f.env.get("USERPROFILE").unwrap())
    }

    fn find<'a>(p: &'a Plan, id: &str) -> Option<&'a PlannedDecoy> {
        p.planned.iter().find(|d| d.decoy_id == id)
    }

    #[test]
    fn plans_primary_locations_on_a_clean_profile() {
        let f = fixture();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let aws = find(&p, "aws-credentials").unwrap();
        assert_eq!(aws.target, home(&f).join(".aws").join("credentials"));
        assert_eq!(aws.candidate_index, 0);
        // No browsers installed in the fixture: browser decoys are skipped.
        assert!(p.skipped.iter().any(
            |s| s.decoy_id == "chrome-login-data" && s.reason == SkipReason::RequirementMissing
        ));
        // Every planted file is inside the profile.
        for d in &p.planned {
            for file in &d.files {
                assert!(is_within(&file.path, &home(&f)), "{}", file.path.display());
            }
        }
    }

    #[test]
    fn installed_tool_moves_decoy_to_alternate_and_never_targets_real_file() {
        let f = fixture();
        let aws = home(&f).join(".aws");
        std::fs::create_dir_all(&aws).unwrap();
        std::fs::write(aws.join("credentials"), "real").unwrap();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let d = find(&p, "aws-credentials").unwrap();
        assert_eq!(d.target, aws.join("credentials.bak"));
        assert!(d.candidate_index > 0);
    }

    #[test]
    fn existing_files_are_never_chosen() {
        let f = fixture();
        let aws = home(&f).join(".aws");
        std::fs::create_dir_all(&aws).unwrap();
        std::fs::write(aws.join("credentials"), "real").unwrap();
        std::fs::write(aws.join("credentials.bak"), "real backup").unwrap();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let d = find(&p, "aws-credentials").unwrap();
        assert_eq!(d.target, home(&f).join(".aws.old").join("credentials"));

        std::fs::create_dir_all(home(&f).join(".aws.old")).unwrap();
        std::fs::write(home(&f).join(".aws.old").join("credentials"), "x").unwrap();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let s = p
            .skipped
            .iter()
            .find(|s| s.decoy_id == "aws-credentials")
            .unwrap();
        assert!(
            matches!(&s.reason, SkipReason::NoAcceptableTarget { rejections } if rejections.len() == 3)
        );
    }

    #[test]
    fn synced_folders_are_rejected() {
        let f = fixture();
        let fs = RealFs {
            synced: vec![SyncedRoot {
                provider: SyncProvider::OneDrive,
                path: home(&f).join("Documents"),
            }],
        };
        let p = plan_with(&f, &fs, &Manifest::default());
        let d = find(&p, "password-export-csv").unwrap();
        assert_eq!(
            d.target,
            home(&f).join("Downloads").join("passwords-export-2024.csv")
        );

        // The whole profile synced: nothing may be planted.
        let fs = RealFs {
            synced: vec![SyncedRoot {
                provider: SyncProvider::Dropbox,
                path: home(&f),
            }],
        };
        let p = plan_with(&f, &fs, &Manifest::default());
        assert!(p.planned.is_empty());
    }

    #[test]
    fn git_working_trees_are_rejected() {
        let f = fixture();
        std::fs::create_dir_all(home(&f).join(".git")).unwrap();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let profile_targets = p
            .planned
            .iter()
            .filter(|d| is_within(&d.target, &home(&f)))
            .count();
        assert_eq!(
            profile_targets, 0,
            "dotfiles repo in profile: plant nothing"
        );
        assert!(p.skipped.iter().any(|s| matches!(&s.reason, SkipReason::NoAcceptableTarget { rejections } if rejections.iter().any(|(_, r)| matches!(r, Rejection::GitTree { .. })))));
    }

    #[test]
    fn fresh_dirs_protect_real_project_and_profile_folders() {
        let f = fixture();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let first = find(&p, "project-dotenv").unwrap().target.clone();
        let project_dir = first.parent().unwrap().to_path_buf();
        // A real project with the same name appears: the decoy must move.
        std::fs::create_dir_all(&project_dir).unwrap();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let moved = find(&p, "project-dotenv").unwrap();
        assert!(!is_within(&moved.target, &project_dir));
    }

    #[test]
    fn wallet_skipped_when_real_wallet_installed() {
        let f = fixture();
        std::fs::create_dir_all(PathBuf::from(f.env.get("APPDATA").unwrap()).join("Exodus"))
            .unwrap();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        assert!(
            p.skipped.iter().any(|s| s.decoy_id == "exodus-seed"
                && matches!(s.reason, SkipReason::RealInstalled { .. }))
        );
    }

    #[test]
    fn browser_profile_planted_only_when_browser_installed() {
        let f = fixture();
        let ud = PathBuf::from(f.env.get("LOCALAPPDATA").unwrap())
            .join("Google")
            .join("Chrome")
            .join("User Data");
        std::fs::create_dir_all(ud.join("Default")).unwrap();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let login = find(&p, "chrome-login-data").unwrap();
        let cookies = find(&p, "chrome-cookies").unwrap();
        // Group fields keep every file in the same decoy profile.
        assert_eq!(
            login.target.parent(),
            cookies.target.parent().and_then(Path::parent)
        );
        assert!(
            login
                .target
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("Profile ")
        );
        assert!(find(&p, "edge-login-data").is_none());
    }

    #[test]
    fn layout_is_stable_per_seed_and_differs_between_seeds() {
        let f = fixture();
        let a = plan_with(&f, &RealFs::default(), &Manifest::default());
        let b = plan_with(&f, &RealFs::default(), &Manifest::default());
        let ta: Vec<_> = a.planned.iter().map(|d| d.target.clone()).collect();
        let tb: Vec<_> = b.planned.iter().map(|d| d.target.clone()).collect();
        assert_eq!(ta, tb);

        let mut differs = false;
        for s in 0..8u8 {
            let mut g = fixture();
            g.seed = InstallSeed::from_bytes([s + 50; 32]);
            let c = Planner {
                catalog: &g.catalog,
                env: &g.env,
                seed: &g.seed,
                fs: &RealFs::default(),
                manifest: &Manifest::default(),
            }
            .plan(&opts(), &mut rand::rng())
            .unwrap();
            let rel = |p: &Plan, h: &Path| -> Vec<String> {
                p.planned
                    .iter()
                    .map(|d| {
                        d.target
                            .strip_prefix(h)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect()
            };
            if rel(&c, &home(&g)) != rel(&a, &home(&f)) {
                differs = true;
            }
        }
        assert!(differs, "different seeds should produce different layouts");
    }

    #[test]
    fn already_planted_decoys_are_skipped_and_partial_ones_completed() {
        let f = fixture();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        let d = find(&p, "aws-credentials").unwrap().clone();
        std::fs::create_dir_all(d.target.parent().unwrap()).unwrap();
        std::fs::write(&d.target, &d.files[0].bytes).unwrap();
        let manifest = Manifest {
            entries: vec![ManifestEntry {
                path: d.target.clone(),
                sha256: String::new(),
                size: 0,
                decoy_id: d.decoy_id.clone(),
                category: d.category,
                target: d.target.clone(),
                planted_at: OffsetDateTime::now_utc(),
                canary: false,
            }],
            dirs: vec![],
        };
        let p = plan_with(&f, &RealFs::default(), &manifest);
        assert!(
            p.skipped
                .iter()
                .any(|s| s.decoy_id == "aws-credentials" && s.reason == SkipReason::AlreadyPlanted)
        );
        // If the decoy was deleted (a stealer took it), it is re-planted in place.
        std::fs::remove_file(&d.target).unwrap();
        let p = plan_with(&f, &RealFs::default(), &manifest);
        assert_eq!(find(&p, "aws-credentials").unwrap().target, d.target);
    }

    #[test]
    fn categories_filter() {
        let f = fixture();
        let mut o = opts();
        o.categories = [Category::Cloud].into_iter().collect();
        let p = Planner {
            catalog: &f.catalog,
            env: &f.env,
            seed: &f.seed,
            fs: &RealFs::default(),
            manifest: &Manifest::default(),
        }
        .plan(&o, &mut rand::rng())
        .unwrap();
        assert!(p.planned.iter().all(|d| d.category == Category::Cloud));
        assert!(!p.planned.is_empty());
    }

    #[test]
    fn canary_values_are_planted() {
        let f = fixture();
        let mut o = opts();
        o.canaries
            .insert("aws_access_key_id".into(), "CANARYKEYID123".into());
        let p = Planner {
            catalog: &f.catalog,
            env: &f.env,
            seed: &f.seed,
            fs: &RealFs::default(),
            manifest: &Manifest::default(),
        }
        .plan(&o, &mut rand::rng())
        .unwrap();
        let d = find(&p, "aws-credentials").unwrap();
        assert!(d.canary);
        assert!(String::from_utf8_lossy(&d.files[0].bytes).contains("CANARYKEYID123"));
    }

    #[test]
    fn rendered_text_decoys_are_well_formed() {
        let f = fixture();
        let p = plan_with(&f, &RealFs::default(), &Manifest::default());
        for id in [
            "claude-code-credentials",
            "claude-code-config",
            "codex-auth",
            "claude-desktop-mcp",
            "gcp-service-account",
            "azure-msal-cache",
        ] {
            let d = find(&p, id).unwrap();
            let text = String::from_utf8(d.files[0].bytes.clone()).unwrap();
            serde_json::from_str::<serde_json::Value>(&text)
                .unwrap_or_else(|e| panic!("{id}: {e}\n{text}"));
        }
        let codex = find(&p, "codex-config").unwrap();
        toml::from_str::<toml::Value>(&String::from_utf8_lossy(&codex.files[0].bytes)).unwrap();
        assert!(f.dir.path().exists());
    }
}
