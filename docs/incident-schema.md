# Incident JSON schema (`schema_version` 1)

`epicurus export <id>` writes `incident-<id>.json`. The same document is returned over IPC and stored in SQLite. Timestamps are RFC 3339 in UTC. Fields may be added in later minor versions; a breaking change bumps `schema_version`.

```jsonc
{
  "schema_version": 1,
  "id": "inc_3f9a0c1d2b4e5f60",           // inc_ + 16 lowercase hex
  "created_at": "2026-11-23T10:15:02.123456Z",
  "updated_at": "2026-11-23T10:15:04.019000Z",
  "simulated": false,                      // produced by `epicurus simulate`
  "score": 95,                             // 0-100
  "severity": "critical",                  // info | low | medium | high | critical
  "reasons": [                             // every contribution to the score
    { "code": "decoy_touched", "points": 40, "detail": "Opened a decoy credential that no legitimate software uses" }
  ],
  "status": "awaiting_decision",           // open | awaiting_decision | resolved
  "process": {
    "pid": 4242,                           // 0 when no process could be attributed
    "ppid": 3120,
    "start_time": "2026-11-23T10:14:58.500000Z",
    "image_path": "C:\\Users\\dev\\AppData\\Local\\Temp\\x.exe",
    "image_sha256": "…64 hex…",
    "image_size": 1843200,
    "image_created": "2026-11-23T10:14:40Z",
    "signature": {
      "status": "unsigned",                // valid | unsigned | invalid | unknown
      "chain": [],                         // subject names, leaf first
      "catalog_signed": false,
      "error": null                        // WinVerifyTrust HRESULT (hex) when invalid
    },
    "command_line": "x.exe --quiet",
    "user": "DESKTOP\\dev",
    "user_sid": "S-1-5-21-…-1001",
    "integrity": "medium",                 // untrusted | low | medium | medium-plus | high | system | protected
    "user_writable_dir": true,
    "temp_or_downloads": true,
    "network": [ { "protocol": "tcp", "local": "10.0.0.5:51234", "remote": "203.0.113.9:443", "state": "ESTABLISHED" } ],
    "modules": [ "C:\\Windows\\SYSTEM32\\ntdll.dll" ],
    "exited": false,                       // exited before triage (data from the process table)
    "protected": false                     // critical or PPL: never contained
  },
  "tree": [                                // ancestors (root first), subject, descendants
    { "pid": 3120, "ppid": 1, "image": "C:\\Windows\\explorer.exe", "command_line": null, "start_time": "…", "role": "ancestor" },
    { "pid": 4242, "ppid": 3120, "image": "…x.exe", "command_line": "…", "start_time": "…", "role": "subject" },
    { "pid": 4300, "ppid": 4242, "image": "…", "command_line": "…", "start_time": "…", "role": "child" }
  ],
  "touches": [
    {
      "at": "2026-11-23T10:15:02.123456Z",
      "decoy_id": "aws-credentials",
      "category": "cloud",                 // ai_agent | mcp | cloud | browser | wallet | messaging | password_manager
      "path": "C:\\Users\\dev\\.aws\\credentials",
      "op": "open",                        // open | read | delete | rename | modify
      "source": "etw",                     // etw | oplock | audit | integrity
      "bytes": null
    }
  ],
  "related_paths": [ "C:\\Users\\dev\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ],
  "timeline": [ { "at": "…", "kind": "oplock", "message": "Oplock tripwire fired on aws-credentials (12 ms before the Etw event)" } ],
  "actions": [
    { "at": "…", "action": "suspend", "actor": "policy", "ok": true, "detail": "suspended 2 process(es): [4242, 4300]" }
  ],
  "suspended_pids": [ 4242, 4300 ],
  "host": "DESKTOP",
  "epicurus_version": "0.1.0"
}
```

## `actions[].action`

`suspend`, `kill_tree`, `resume`, `quarantine`, `block_network`, `allowlist`, `minidump`, `dismiss`. `actor` is `policy` or `user`.

## `reasons[].code`

| Code | Meaning |
|---|---|
| `decoy_touched` | a decoy was opened (+40) |
| `multiple_decoys` | +8 per additional distinct decoy, up to +24 |
| `two_categories` | decoys in exactly two categories (+15) |
| `category_sweep` | three or more categories within the sweep window; raises the score to at least 90 |
| `read_data` | data was read (+5; audit mode) |
| `destructive` | a decoy was deleted, renamed or modified (+15) |
| `unsigned` | image not signed (+15) |
| `bad_signature` | signature invalid or untrusted (+20) |
| `trusted_signature` | valid, trusted signature (−20) |
| `temp_or_downloads` | image in %TEMP%, Downloads or C:\Windows\Temp (+15) |
| `user_writable_dir` | image elsewhere user-writable (+10) |
| `new_image` | image file created less than 24 h ago (+10) |
| `real_secrets_opened` | the process also opened real credential stores (+10) |
| `network` | non-listening network connections (+5) |
| `script_parent` | parent is a script host or LOLBin (+5) |
| `unattributed` | oplock tripwires fired without process attribution (0; informational) |

## Other exports

- `incident-<id>.html`: a self-contained report (inline CSS, no scripts, no external requests; a restrictive Content-Security-Policy meta tag). It covers summary, score explanation, process, tree, decoys touched, real stores opened, network, timeline, actions, modules, and recommended next steps: which real secret categories to rotate, persistence locations to check, and how to scan the system. All process-derived text is HTML-escaped.
- `incident-<id>.stix.json`: a STIX 2.1 bundle containing an `identity` (Epicurus), `file` (name, SHA-256, size), `process` (pid, command line, created time, image ref), `ipv4-addr`/`ipv6-addr` and `network-traffic` for remote endpoints, an `observed-data` tying them together, and `indicator`s for the image hash and each remote address (`pattern_type: stix`, labels `epicurus` or `epicurus-simulation`).
