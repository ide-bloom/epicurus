//! Incident exports: structured JSON, a self-contained offline HTML report and
//! a STIX 2.1 bundle of indicators.

pub mod html;
pub mod stix;

use std::path::{Path, PathBuf};

use crate::catalog::Category;
use crate::incident::Incident;
use crate::{Error, Result};

/// Pretty JSON for `incident-<id>.json`.
pub fn to_json(inc: &Incident) -> Result<String> {
    Ok(serde_json::to_string_pretty(inc)?)
}

/// Writes JSON, HTML and STIX files into `dir`; returns the paths written.
pub fn export_all(inc: &Incident, dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
    let files = [
        (format!("incident-{}.json", inc.id), to_json(inc)?),
        (format!("incident-{}.html", inc.id), html::render(inc)),
        (format!("incident-{}.stix.json", inc.id), stix::bundle(inc)?),
    ];
    let mut out = Vec::new();
    for (name, body) in files {
        let p = dir.join(name);
        std::fs::write(&p, body).map_err(|e| Error::io(&p, e))?;
        out.push(p);
    }
    Ok(out)
}

/// Real secret categories the user should rotate, derived from what the
/// stealer went after. A stealer that reached the decoys almost certainly
/// read the real files next to them.
pub fn rotation_advice(categories: &[Category]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for c in categories {
        out.extend_from_slice(match c {
            Category::AiAgent => &[
                "AI coding agent sessions: sign out of Claude Code, Codex, Cursor, Windsurf, Gemini CLI and GitHub Copilot on every device and revoke their OAuth grants",
                "AI provider API keys (Anthropic, OpenAI, Google AI): revoke and reissue",
            ][..],
            Category::Mcp => &[
                "Every key embedded in MCP server configs: GitHub PATs, Slack bot tokens, Notion integrations, database passwords, Stripe keys",
            ][..],
            Category::Cloud => &[
                "Cloud credentials: AWS access keys, Azure CLI sessions, gcloud credentials and service account keys",
                "Developer tokens: npm, PyPI, Docker registries, git credential helper entries, kubeconfig tokens and certificates",
                "SSH keys: generate new keys and remove the old public keys from every server and forge",
                "Secrets in local .env files of every project on this machine",
            ][..],
            Category::Browser => &[
                "Every password saved in your browsers, starting with email, cloud consoles and code hosting",
                "Browser sessions: sign out of all sessions on Google, Microsoft, GitHub and other critical sites (session cookies bypass MFA)",
            ][..],
            Category::Wallet => &[
                "Crypto wallets: move funds to a new wallet created on a clean device; treat existing seed phrases as compromised",
            ][..],
            Category::Messaging => &[
                "Telegram: terminate all other sessions; Discord: change password to invalidate tokens",
            ][..],
            Category::PasswordManager => &[
                "Your password manager master password, and every credential in any plaintext export on this machine",
            ][..],
        });
    }
    out.dedup();
    out
}

/// Persistence locations worth checking after an infostealer hit.
pub const PERSISTENCE_CHECKS: &[&str] = &[
    r"Run keys: HKCU\Software\Microsoft\Windows\CurrentVersion\Run and RunOnce (and the HKLM equivalents)",
    r"Startup folders: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup and %ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp",
    "Scheduled tasks: Task Scheduler library, especially tasks running from %APPDATA%, %LOCALAPPDATA% or %TEMP%",
    "Services: recently created services with binaries outside Program Files or System32",
    "WMI event subscriptions (root\\subscription __EventFilter / CommandLineEventConsumer)",
    "Browser extensions installed recently in every browser profile",
    "Developer tooling: npm global packages, VS Code / Cursor extensions, MCP servers and git hooks you did not install",
];

/// Scan guidance.
pub const SCAN_STEPS: &[&str] = &[
    "Disconnect the machine from the network if exfiltration may still be in progress",
    "Run a Microsoft Defender full scan, then a Microsoft Defender Offline scan (Windows Security > Virus & threat protection > Scan options)",
    "Get a second opinion from a reputable on-demand scanner",
    "Review the process image hash in this report against VirusTotal or your EDR",
    "If the machine holds production credentials, consider reimaging after rotating secrets from a clean device",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advice_covers_every_category() {
        for c in Category::ALL {
            assert!(!rotation_advice(&[c]).is_empty());
        }
    }
}
