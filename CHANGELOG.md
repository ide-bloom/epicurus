# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-23

### Added

- Decoy engine with a data-driven catalog of 47 decoys across AI coding agents, MCP server configs, cloud and developer credentials, browser stores, crypto wallets, messaging sessions and password-manager exports; user overrides in `catalog.d`.
- Format-accurate secret generators (AWS, GitHub, Anthropic, OpenAI, Google, Slack, Stripe, Notion, npm, PyPI, Discord, Telegram, Azure, JWT, OpenSSH ed25519 and more) with deliberately failing checksums where formats carry one; live canary support.
- Planting safety: `CREATE_NEW` creation, manifest with SHA-256, hash-checked unplanting, real-tool alternates, fresh-directory rules, cloud-sync and git-tree exclusion, per-install seeded layouts, backdated timestamps and user ownership.
- Sensors: Kernel-File and Kernel-Process real-time ETW with TDH decoding, oplock tripwire (RWH with RH fallback), `ReadDirectoryChangesW` integrity watcher, SACL plus Security 4663 fallback, PID+start-time process table.
- Triage: image hash, Authenticode (embedded and catalog) with signer chain, parent chain, command line, user, integrity, location, image age, related credential stores, network connections and modules.
- Explainable 0–100 scoring with severity bands and category-sweep detection; data-driven allowlist (signer + path, or hash).
- Containment: process-tree suspension, kill, resume, quarantine with execute-deny ACL, firewall outbound block, allowlist, optional minidump; critical and PPL processes are never contained.
- Alerts: toasts with Kill / Resume / Open, Windows Event Log with documented IDs, Discord, Slack, ntfy and HMAC-signed JSON webhooks; DPAPI-protected secrets, deduplication and rate limiting.
- Incident exports: JSON, self-contained HTML and STIX 2.1.
- Windows service with ACL'd named-pipe IPC, tray agent launched into the user's session, egui dashboard.
- CLI: `install`, `uninstall`, `plant`, `unplant`, `status`, `ui`, `incidents`, `export`, `simulate`, `doctor`.
- CI (fmt, clippy, tests, elevated integration test, cargo-deny, x64 and ARM64 builds) and tag-driven releases with SHA256SUMS and build provenance attestations.

[Unreleased]: https://github.com/ide-bloom/epicurus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ide-bloom/epicurus/releases/tag/v0.1.0
