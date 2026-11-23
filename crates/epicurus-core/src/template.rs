//! Placeholder templates used by catalog paths and file contents.
//!
//! Syntax:
//! * `{{field}}` inserts a generated field value.
//! * `{{field.part}}` inserts a named sub-value (e.g. `{{ssh.public}}`).
//! * `{{field|json}}` escapes the value for use inside a JSON string; the
//!   other filters are `b64`, `upper` and `lower`.
//! * `{{@snippet}}` inserts a shared catalog snippet, rendered with the same
//!   fields.
//!
//! Templates never contain secret literals; every secret is a placeholder.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::generators::Generated;
use crate::{Error, Result};

const MAX_SNIPPET_DEPTH: usize = 4;

/// Values and snippets available while rendering.
pub struct RenderScope<'a> {
    /// Generated field values.
    pub fields: &'a BTreeMap<String, Generated>,
    /// Shared snippets.
    pub snippets: &'a BTreeMap<String, String>,
}

/// Renders `template`, failing on unknown placeholders so a catalog typo is
/// caught instead of producing an obviously fake decoy.
pub fn render(template: &str, scope: &RenderScope<'_>) -> Result<String> {
    render_depth(template, scope, 0)
}

fn render_depth(template: &str, scope: &RenderScope<'_>, depth: usize) -> Result<String> {
    if depth > MAX_SNIPPET_DEPTH {
        return Err(Error::Template("snippets nested too deeply".into()));
    }
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .ok_or_else(|| Error::Template("unterminated {{ placeholder".into()))?;
        let token = after[..end].trim();
        out.push_str(&resolve(token, scope, depth)?);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve(token: &str, scope: &RenderScope<'_>, depth: usize) -> Result<String> {
    if let Some(name) = token.strip_prefix('@') {
        let snippet = scope
            .snippets
            .get(name)
            .ok_or_else(|| Error::Template(format!("unknown snippet {name:?}")))?;
        return render_depth(snippet, scope, depth + 1);
    }
    let (path, filter) = match token.split_once('|') {
        Some((p, f)) => (p.trim(), Some(f.trim())),
        None => (token, None),
    };
    let (field, part) = match path.split_once('.') {
        Some((f, p)) => (f, Some(p)),
        None => (path, None),
    };
    let generated = scope
        .fields
        .get(field)
        .ok_or_else(|| Error::Template(format!("unknown field {field:?}")))?;
    let value = match part {
        None => generated.value.clone(),
        Some(p) => generated
            .parts
            .get(p)
            .cloned()
            .ok_or_else(|| Error::Template(format!("field {field:?} has no part {p:?}")))?,
    };
    apply_filter(value, filter)
}

fn apply_filter(value: String, filter: Option<&str>) -> Result<String> {
    Ok(match filter {
        None => value,
        Some("json") => json_escape(&value),
        Some("b64") => base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
        Some("upper") => value.to_uppercase(),
        Some("lower") => value.to_lowercase(),
        Some(other) => return Err(Error::Template(format!("unknown filter {other:?}"))),
    })
}

/// Escapes a string for embedding inside a JSON string literal.
pub fn json_escape(s: &str) -> String {
    let quoted = serde_json::Value::String(s.to_string()).to_string();
    quoted[1..quoted.len() - 1].to_string()
}

/// Field names referenced by a template (excluding snippets' own fields).
pub fn referenced_fields(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let token = after[..end].trim();
        if !token.starts_with('@') {
            let path = token.split('|').next().unwrap_or_default().trim();
            let field = path.split('.').next().unwrap_or_default();
            if !field.is_empty() && !out.iter().any(|f| f == field) {
                out.push(field.to_string());
            }
        }
        rest = &after[end + 2..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> BTreeMap<String, Generated> {
        let mut f = BTreeMap::new();
        f.insert(
            "key".into(),
            Generated {
                value: "line1\nline\"2".into(),
                parts: [("public".to_string(), "PUB".to_string())]
                    .into_iter()
                    .collect(),
                canary: false,
            },
        );
        f.insert(
            "user".into(),
            Generated {
                value: "jdoe".into(),
                ..Default::default()
            },
        );
        f
    }

    #[test]
    fn renders_fields_parts_filters_and_snippets() {
        let f = fields();
        let mut s = BTreeMap::new();
        s.insert("greet".to_string(), "hi {{user|upper}}".to_string());
        let scope = RenderScope {
            fields: &f,
            snippets: &s,
        };
        assert_eq!(
            render("{{user}}:{{key.public}}", &scope).unwrap(),
            "jdoe:PUB"
        );
        assert_eq!(render("{{key|json}}", &scope).unwrap(), "line1\\nline\\\"2");
        assert_eq!(render("{{@greet}}!", &scope).unwrap(), "hi JDOE!");
        assert_eq!(render("{{ user | b64 }}", &scope).unwrap(), "amRvZQ==");
    }

    #[test]
    fn rejects_unknown_placeholders() {
        let f = fields();
        let s = BTreeMap::new();
        let scope = RenderScope {
            fields: &f,
            snippets: &s,
        };
        assert!(render("{{nope}}", &scope).is_err());
        assert!(render("{{key.private}}", &scope).is_err());
        assert!(render("{{user|rot13}}", &scope).is_err());
        assert!(render("{{@missing}}", &scope).is_err());
        assert!(render("{{user", &scope).is_err());
    }

    #[test]
    fn snippet_recursion_is_bounded() {
        let f = fields();
        let mut s = BTreeMap::new();
        s.insert("loop".to_string(), "{{@loop}}".to_string());
        let scope = RenderScope {
            fields: &f,
            snippets: &s,
        };
        assert!(render("{{@loop}}", &scope).is_err());
    }

    #[test]
    fn lists_referenced_fields() {
        assert_eq!(
            referenced_fields("{{a}} {{b.part}} {{a|json}} {{@snip}}"),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
