# Threat model

## What Epicurus defends against

Commodity and targeted **infostealers running as the user** (medium integrity) that harvest credentials from well-known locations: AI coding-agent tokens and MCP configs, cloud CLIs, package registries, SSH keys, `.env` files, browser stores, wallets and messaging sessions. Typical delivery is a fake installer, a malicious package or extension, or a cracked tool.

Goals:

1. **Detect** the theft attempt the moment a decoy is opened, with very few false positives.
2. **Attribute** it to a specific process (PID + start time, image, hash, signer, parent chain), even if that process has already exited.
3. **Contain** it by suspending the process tree before it finishes collecting or exfiltrating.
4. **Report** it with enough evidence to decide what to rotate and what to clean.

## Assets

- The user's real secrets. Epicurus never reads, copies or modifies them; it only notes *that* a suspect process opened a real store (by path, from ETW).
- The decoys' integrity: modifications are detected and logged.
- Epicurus's own configuration and evidence: `%ProgramData%\Epicurus` is SYSTEM/Administrators-only, and alert secrets are DPAPI-protected under LocalSystem.

## Trust boundaries

| Boundary | Control |
|---|---|
| User session ↔ service | Named pipe DACL (SYSTEM, Administrators, installing user), remote clients rejected, first-instance flag, server-PID verification by clients, strict message validation with size caps |
| Service binary | Installed to `%ProgramFiles%\Epicurus` with an admin-only write ACL |
| Data directory | Protected DACL, SYSTEM and Administrators only |
| Alert secrets | DPAPI (LocalSystem scope plus Epicurus-specific entropy); never returned over IPC |
| Outbound traffic | Only to webhook endpoints the user configured; TLS via rustls with the platform verifier |

## Limitations (read these)

### Kernel-level malware

A rootkit or malicious driver can intercept file system operations, hide from or tamper with ETW providers, or terminate any process. Epicurus runs in user mode and cannot defend against code running in the kernel. Use HVCI/Memory Integrity, Secure Boot and a driver blocklist.

### Admin-level malware and ETW tampering

Malware running as Administrator or SYSTEM can stop the ETW session, patch the provider in its own process, stop or delete the service, add itself to the allowlist file, clear the Event Log, or remove the decoys. Mitigations within reach:

- the engine notices its consumer stopping and restarts it or falls back to auditing, logging events 1003/1004;
- the oplock tripwire is independent of ETW: a break with no attributed process is logged (2030), and several such breaks raise an incident without a process;
- off-box alert channels (webhooks, ntfy) deliver before local evidence can be erased.

These raise the cost; they do not stop an attacker who already owns the machine.

### Stealers that check for decoys

A stealer could try to fingerprint decoys: an implausible owner, fresh timestamps, files that fail a format check, identical layouts across machines, or a known installer artifact. Epicurus counters with:

- formats that match real files (OpenSSH key structure, SQLite schemas from Chromium and VS Code, LevelDB logs with valid CRC32C, provider token formats);
- the protected user as file owner, backdated timestamps, varied sizes;
- per-install seeded layouts (directory names, profile numbers, account names), so no static blocklist works;
- no marker files and no "epicurus" strings inside decoys.

A determined adversary can still try, for example by validating a token against the provider's API, which would itself be a strong signal to the provider. Live canaries make that a detection too.

### Race windows

Detection happens at open time. Before touching a decoy, a stealer may already have read real secrets. After the open, it holds decoy bytes until suspension, which takes milliseconds to a second or two depending on the sensor path. Suspension stops further collection and exfiltration from the suspended tree, but it cannot undo what was read. **Treat any real (non-simulated) incident as a compromise: rotate the secrets listed in the report from a clean device.**

Processes outside the suspended tree (an injected-into browser, a persistence mechanism created earlier) are not contained automatically. The report lists persistence locations to check.

### Coverage

- Only decoys that exist can be tripped. A stealer that reads one specific real file for which no decoy exists goes unseen by Epicurus.
- Real installations are protected by *alternate* decoy locations (`.bak`, legacy names). A stealer that reads only the exact real path of an installed tool may skip the decoy.
- Browser decoys appear only for installed browsers, and wallet decoys only where the real wallet is absent.
- One protected user per installation.

### False positives

Legitimate software rarely opens these files. Likely sources are backup tools, antivirus scans, file indexers, sync clients (but decoys are never placed in synced folders), and users browsing hidden folders with an editor. Defaults allowlist Microsoft Defender, Windows Search and common backup agents by signer and path. Signed software scores lower, and the default policy suspends only high and critical incidents.

### Availability

Suspending a falsely accused process freezes it until you decide. The dashboard, the toast and `epicurus status` show pending decisions. Resuming restores it exactly.

## Non-goals

- Replacing antivirus or EDR.
- Network-level exfiltration blocking (beyond per-image firewall rules on request).
- Protecting secrets that live only in memory or in OS-protected vaults.
