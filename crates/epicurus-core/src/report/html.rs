//! Self-contained, offline HTML incident report.
//!
//! No external assets, no scripts: everything is inline CSS and static
//! markup. Every value that came from the attacker's process (command lines,
//! paths, module names) is HTML-escaped.

use std::fmt::Write as _;

use crate::incident::{Incident, IncidentStatus, SignatureStatus};
use crate::timefmt::rfc3339;

/// HTML-escapes text for element content and quoted attributes.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {
                let _ = write!(out, "&#x{:x};", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root { --bg:#0f1115; --panel:#171a21; --text:#e6e8ee; --muted:#9aa3b2; --line:#272c36;
  --crit:#e5484d; --high:#f76b15; --med:#ffb224; --low:#3e9bff; --info:#8b95a5; --ok:#30a46c; }
@media (prefers-color-scheme: light) { :root { --bg:#f7f8fa; --panel:#fff; --text:#11151c; --muted:#5b6475; --line:#e3e6ec; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI", system-ui, sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:16px; margin:28px 0 10px; border-bottom:1px solid var(--line); padding-bottom:6px; }
.muted { color:var(--muted); } .mono { font-family: "Cascadia Mono", Consolas, monospace; font-size:12.5px; word-break:break-all; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-weight:600; font-size:12px; color:#fff; text-transform:uppercase; letter-spacing:.04em; }
.critical{background:var(--crit)} .high{background:var(--high)} .medium{background:var(--med);color:#111} .low{background:var(--low)} .info{background:var(--info)}
.grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
.card .k { color:var(--muted); font-size:12px; } .card .v { font-size:18px; font-weight:600; }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
tr:last-child td { border-bottom:none; }
.pos { color:var(--crit); } .neg { color:var(--ok); }
ol, ul { margin:6px 0; padding-left:22px; } li { margin:3px 0; }
.tree div { padding:2px 0; }
.sim { background:var(--med); color:#111; padding:8px 12px; border-radius:6px; font-weight:600; margin:12px 0; }
"#;

/// Renders the report.
pub fn render(inc: &Incident) -> String {
    let mut h = String::with_capacity(32 * 1024);
    let sev = inc.severity.as_str();
    let p = &inc.process;
    let title = format!("Epicurus incident {}", inc.id);
    let _ = write!(
        h,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <title>{}</title><style>{STYLE}</style></head><body><main>",
        escape(&title)
    );
    let _ = write!(
        h,
        "<h1>{} <span class=\"badge {sev}\">{sev} &middot; {}/100</span></h1><div class=\"muted\">Host {} &middot; created {} &middot; Epicurus {}</div>",
        escape(&title),
        inc.score,
        escape(&inc.host),
        escape(&rfc3339(inc.created_at)),
        escape(&inc.epicurus_version)
    );
    if inc.simulated {
        h.push_str("<div class=\"sim\">SIMULATED INCIDENT: produced by <code>epicurus simulate</code>. No real stealer was involved.</div>");
    }

    let status = match inc.status {
        IncidentStatus::Open => "Open",
        IncidentStatus::AwaitingDecision => "Suspended, awaiting decision",
        IncidentStatus::Resolved => "Resolved",
    };
    let sig = match p.signature.status {
        SignatureStatus::Valid => "Valid",
        SignatureStatus::Unsigned => "Unsigned",
        SignatureStatus::Invalid => "Invalid / untrusted",
        SignatureStatus::Unknown => "Unknown",
    };
    let _ = write!(
        h,
        "<h2>Summary</h2><div class=\"grid\">\
         <div class=\"card\"><div class=\"k\">Process</div><div class=\"v mono\">{} (PID {})</div></div>\
         <div class=\"card\"><div class=\"k\">Decoys touched</div><div class=\"v\">{}</div></div>\
         <div class=\"card\"><div class=\"k\">Categories</div><div class=\"v\">{}</div></div>\
         <div class=\"card\"><div class=\"k\">Status</div><div class=\"v\">{}</div></div></div>",
        escape(file_name(&p.image_path)),
        p.pid,
        inc.distinct_decoys(),
        escape(
            &inc.distinct_categories()
                .iter()
                .map(|c| c.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        status
    );

    h.push_str("<h2>Score explanation</h2><table><tr><th>Points</th><th>Reason</th></tr>");
    for r in &inc.reasons {
        let cls = if r.points > 0 {
            "pos"
        } else if r.points < 0 {
            "neg"
        } else {
            "muted"
        };
        let _ = write!(
            h,
            "<tr><td class=\"{cls}\">{:+}</td><td>{}</td></tr>",
            r.points,
            escape(&r.detail)
        );
    }
    h.push_str("</table>");

    h.push_str("<h2>Process</h2><table>");
    let row = |h: &mut String, k: &str, v: &str| {
        let _ = write!(
            h,
            "<tr><th>{}</th><td class=\"mono\">{}</td></tr>",
            escape(k),
            escape(v)
        );
    };
    row(&mut h, "Image", &p.image_path);
    row(
        &mut h,
        "SHA-256",
        p.image_sha256.as_deref().unwrap_or("unknown"),
    );
    row(
        &mut h,
        "Signature",
        &format!(
            "{sig}{}",
            if p.signature.catalog_signed {
                " (catalog)"
            } else {
                ""
            }
        ),
    );
    row(
        &mut h,
        "Signer chain",
        &if p.signature.chain.is_empty() {
            "none".to_string()
        } else {
            p.signature.chain.join(" > ")
        },
    );
    row(
        &mut h,
        "Command line",
        p.command_line.as_deref().unwrap_or("unknown"),
    );
    row(
        &mut h,
        "User",
        &format!(
            "{} {}",
            p.user.as_deref().unwrap_or("unknown"),
            p.user_sid.as_deref().unwrap_or("")
        ),
    );
    row(
        &mut h,
        "Integrity",
        p.integrity.as_deref().unwrap_or("unknown"),
    );
    row(
        &mut h,
        "Started",
        &p.start_time
            .map(rfc3339)
            .unwrap_or_else(|| "unknown".into()),
    );
    row(
        &mut h,
        "Image created",
        &p.image_created
            .map(rfc3339)
            .unwrap_or_else(|| "unknown".into()),
    );
    row(
        &mut h,
        "User-writable location",
        if p.user_writable_dir { "yes" } else { "no" },
    );
    row(
        &mut h,
        "Exited before triage",
        if p.exited { "yes" } else { "no" },
    );
    h.push_str("</table>");

    h.push_str("<h2>Process tree</h2><div class=\"card tree mono\">");
    for n in &inc.tree {
        let indent = match n.role.as_str() {
            "subject" => "&rarr; ",
            "child" => "&nbsp;&nbsp;&nbsp;&nbsp;&#8627; ",
            _ => "",
        };
        let _ = write!(
            h,
            "<div>{indent}<b>{}</b> (PID {}){}</div>",
            escape(&n.image),
            n.pid,
            n.command_line
                .as_ref()
                .map(|c| format!(" <span class=\"muted\">{}</span>", escape(c)))
                .unwrap_or_default()
        );
    }
    if inc.tree.is_empty() {
        h.push_str("<div class=\"muted\">Not available</div>");
    }
    h.push_str("</div>");

    h.push_str("<h2>Decoys touched</h2><table><tr><th>Time</th><th>Decoy</th><th>Operation</th><th>Sensor</th><th>Path</th></tr>");
    for t in &inc.touches {
        let _ = write!(
            h,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{:?}{}</td><td>{:?}</td><td class=\"mono\">{}</td></tr>",
            escape(&rfc3339(t.at)),
            escape(&t.decoy_id),
            t.op,
            t.bytes.map(|b| format!(" ({b} B)")).unwrap_or_default(),
            t.source,
            escape(&t.path)
        );
    }
    h.push_str("</table>");

    if !inc.related_paths.is_empty() {
        h.push_str("<h2>Real credential stores also opened</h2><ul class=\"mono\">");
        for r in &inc.related_paths {
            let _ = write!(h, "<li>{}</li>", escape(r));
        }
        h.push_str("</ul>");
    }

    h.push_str("<h2>Network connections</h2>");
    if p.network.is_empty() {
        h.push_str("<div class=\"muted\">None observed at triage time.</div>");
    } else {
        h.push_str("<table><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th></tr>");
        for c in &p.network {
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                escape(&c.protocol),
                escape(&c.local),
                escape(&c.remote),
                escape(&c.state)
            );
        }
        h.push_str("</table>");
    }

    h.push_str("<h2>Timeline</h2><table><tr><th>Time</th><th>Event</th><th>Detail</th></tr>");
    for e in &inc.timeline {
        let _ = write!(
            h,
            "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td></tr>",
            escape(&rfc3339(e.at)),
            escape(&e.kind),
            escape(&e.message)
        );
    }
    h.push_str("</table>");

    h.push_str("<h2>Actions taken</h2>");
    if inc.actions.is_empty() {
        h.push_str("<div class=\"muted\">None.</div>");
    } else {
        h.push_str("<table><tr><th>Time</th><th>Action</th><th>By</th><th>Result</th></tr>");
        for a in &inc.actions {
            let _ = write!(
                h,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{:?}</td><td>{}{}</td></tr>",
                escape(&rfc3339(a.at)),
                a.action.as_str(),
                a.actor,
                if a.ok { "ok: " } else { "failed: " },
                escape(&a.detail)
            );
        }
        h.push_str("</table>");
    }

    if !p.modules.is_empty() {
        let _ = write!(
            h,
            "<h2>Loaded modules ({})</h2><ul class=\"mono\">",
            p.modules.len()
        );
        for m in &p.modules {
            let _ = write!(h, "<li>{}</li>", escape(m));
        }
        h.push_str("</ul>");
    }

    h.push_str(
        "<h2>Recommended next steps</h2><h3>1. Rotate these secrets (from a clean device)</h3><ol>",
    );
    for a in super::rotation_advice(&inc.distinct_categories()) {
        let _ = write!(h, "<li>{}</li>", escape(a));
    }
    h.push_str("</ol><h3>2. Check persistence locations</h3><ul>");
    for c in super::PERSISTENCE_CHECKS {
        let _ = write!(h, "<li>{}</li>", escape(c));
    }
    h.push_str("</ul><h3>3. Scan the system</h3><ol>");
    for s in super::SCAN_STEPS {
        let _ = write!(h, "<li>{}</li>", escape(s));
    }
    h.push_str("</ol><p class=\"muted\">The decoy values in this report were randomly generated by Epicurus and are not valid credentials.</p></main></body></html>\n");
    h
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::ProcessProfile;
    use time::OffsetDateTime;

    #[test]
    fn escapes_attacker_controlled_fields() {
        let mut inc = Incident::new(
            ProcessProfile {
                image_path: r"C:\Temp\<script>alert(1)</script>.exe".into(),
                command_line: Some("\"x\" <img src=x onerror=alert(1)>".into()),
                ..Default::default()
            },
            OffsetDateTime::now_utc(),
            "host&co".into(),
        );
        inc.related_paths.push("<b>".into());
        let out = render(&inc);
        assert!(!out.contains("<script>alert"));
        assert!(!out.contains("<img src=x"));
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("host&amp;co"));
    }

    #[test]
    fn is_self_contained() {
        let out = render(&Incident::new(
            ProcessProfile::default(),
            OffsetDateTime::now_utc(),
            "h".into(),
        ));
        assert!(!out.contains("http://"));
        assert!(!out.contains("src="));
        assert!(!out.contains("<script"));
        assert!(!out.contains("<link"));
        assert!(out.contains("Recommended next steps"));
    }

    #[test]
    fn simulated_banner() {
        let mut inc = Incident::new(
            ProcessProfile::default(),
            OffsetDateTime::now_utc(),
            "h".into(),
        );
        inc.simulated = true;
        assert!(render(&inc).contains("SIMULATED INCIDENT"));
    }

    #[test]
    fn escape_basics() {
        assert_eq!(escape("a&b<c>\"'"), "a&amp;b&lt;c&gt;&quot;&#39;");
        assert_eq!(escape("\u{1b}"), "&#x1b;");
    }
}
