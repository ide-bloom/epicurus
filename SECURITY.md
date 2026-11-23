# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's [private vulnerability reporting](https://github.com/ide-bloom/epicurus/security/advisories/new). Do not open a public issue.

Include the affected version, your Windows edition and build, reproduction steps, and the impact you believe it has. We aim to acknowledge reports within 3 business days and to ship a fix or mitigation for confirmed high-severity issues within 30 days, coordinating disclosure with you.

## Scope

In scope, for example:

- privilege escalation through the service, the named pipe or the install layout;
- IPC messages that crash the service, bypass validation or act on unintended processes;
- ways for an unprivileged process to read Epicurus's data directory or alert secrets;
- any case where Epicurus modifies or deletes a file it did not create;
- decoy content that would be a valid credential;
- unsafe handling of attacker-controlled data in reports (HTML injection) or toasts.

Out of scope: limitations already described in [docs/threat-model.md](docs/threat-model.md), such as kernel-level malware, attackers who already have administrator rights, and decoy fingerprinting in general.

## Supported versions

Only the latest release receives security fixes.
