//! Keeps the documentation honest: every generator, category and score
//! reason code the code knows about must be documented, and the README and
//! CHANGELOG must state the real catalog size.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use epicurus_core::catalog::{Catalog, Category};
use epicurus_core::generators::GENERATOR_NAMES;
use epicurus_core::scoring::REASON_CODES;

fn repo_file(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn every_generator_is_documented() {
    let doc = repo_file("docs/decoy-catalog.md");
    for g in GENERATOR_NAMES {
        assert!(
            doc.contains(&format!("`{g}")),
            "generator {g} missing from docs/decoy-catalog.md"
        );
    }
}

#[test]
fn every_category_is_documented() {
    let doc = repo_file("docs/decoy-catalog.md");
    let schema = repo_file("docs/incident-schema.md");
    for c in Category::ALL {
        assert!(
            doc.contains(&format!("`{}`", c.as_str())),
            "category {c} missing from docs/decoy-catalog.md"
        );
        assert!(
            schema.contains(c.as_str()),
            "category {c} missing from docs/incident-schema.md"
        );
    }
}

#[test]
fn every_reason_code_is_documented() {
    let schema = repo_file("docs/incident-schema.md");
    let arch = repo_file("docs/architecture.md");
    for code in REASON_CODES {
        assert!(
            schema.contains(&format!("`{code}`")),
            "reason {code} missing from docs/incident-schema.md"
        );
        // `unattributed` is informational (0 points) and described in prose.
        if *code != "unattributed" {
            assert!(
                arch.contains(code),
                "reason {code} missing from docs/architecture.md"
            );
        }
    }
}

#[test]
fn readme_and_changelog_state_the_real_catalog_size() {
    let n = Catalog::embedded().unwrap().decoys.len();
    assert!(
        repo_file("README.md").contains(&format!("up to {n} decoys")),
        "README decoy count is stale ({n})"
    );
    assert!(
        repo_file("CHANGELOG.md").contains(&format!("catalog of {n} decoys")),
        "CHANGELOG decoy count is stale ({n})"
    );
}

#[test]
fn every_catalog_decoy_has_a_description() {
    for d in Catalog::embedded().unwrap().decoys {
        assert!(
            !d.description.trim().is_empty(),
            "decoy {} has no description",
            d.id
        );
    }
}
