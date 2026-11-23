# Architecture

## Crates

| Crate | Role |
|---|---|
| `epicurus-core` | Platform-independent logic: catalog, generators, templates, planner and its safety rules, planting and unplanting, manifest, config, allowlist, scoring, incident model, SQLite storage, report rendering (JSON, HTML, STIX), IPC protocol and blocking client. Unit-testable without admin rights. |
| `epicurus-sensor` | Windows sensors and actions: Kernel-File/Kernel-Process ETW consumer, oplock tripwire, `ReadDirectoryChangesW` integrity watcher, SACL + 4663 fallback, process table, triage (Authenticode, network, modules, token), containment, firewall, ACL helpers. |
| `epicurus-service` | The detection engine, alert dispatch, Event Log, named-pipe IPC server, SCM integration, tray-agent launch. |
| `epicurus-ui` | egui dashboard, tray agent, toasts. Runs unprivileged. |
| `epicurus-cli` | `epicurus.exe`: subcommands, elevation, install/uninstall, simulator, embedded resources (icon, manifest, version info, Event Log message table). |

## Privilege split

```
 user session (unprivileged)                 session 0 (LocalSystem)
 ┌───────────────────────────┐   named pipe   ┌─────────────────────────────┐
 │ epicurus ui    (dashboard)│◄──────────────►│ epicurus service            │
 │ epicurus ui --tray (toast)│ \\.\pipe\       │  engine, sensors,           │
 │ epicurus status/incidents │  epicurus-v1    │  containment, alerts, SQLite│
 └───────────────────────────┘                └─────────────────────────────┘
```

- The **service** owns sensors, containment and storage. `%ProgramData%\Epicurus` carries the DACL `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, so only SYSTEM and Administrators can read incidents or config.
- The **pipe** DACL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;<installing user SID>)`. Remote clients are rejected (`PIPE_REJECT_REMOTE_CLIENTS`). The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a process that squats the name makes the service fail loudly instead of silently impersonating it. Clients on the default pipe also check that `GetNamedPipeServerProcessId` equals the service's PID from the SCM before trusting replies.
- **Protocol.** Frames are a 4-byte little-endian length plus UTF-8 JSON `{ "v": 1, "id": n, "req": { "type": ... } }`. The server refuses frames over 256 KiB before allocating, rejects unknown fields (`deny_unknown_fields`) and range-checks every value (`Request::validate`). Incident ids must match `inc_[0-9a-f]{16}`, webhook URLs must match their provider, and `suspend` and `minidump` are not client-invokable. Mutating requests are logged with the client PID.
- **Tray agent.** Toasts and the notification icon must run in the user's session. A console program started from a Run key flashes a terminal, so instead the service launches `epicurus ui --tray` with `WTSQueryUserToken` + `CreateProcessAsUserW` (`CREATE_NO_WINDOW`), at service start and on `SERVICE_CONTROL_SESSIONCHANGE` logon events, only for the protected user's SID. A session-local mutex keeps one agent per session.

## Event flow

```
ETW callback ─┐
oplock IOCP ──┼─► std::mpsc ─► engine thread ─► lock(Engine) ─► on_sensor_event / tick
integrity ────┤                                         │
4663 callback ┘                     IPC tasks ─► spawn_blocking ─► lock(Engine) ─► handle(request)
                                                          │
                                         tokio mpsc ─► alert dispatcher (reqwest/rustls)
                                         broadcast  ─► subscribed clients (tray toasts)
```

The sensor callbacks do the minimum (decode, filter, send). All state lives in one `Engine` behind a mutex, so the engine needs no internal synchronization. Process-start enrichment (opening the process for its command line and token) happens before taking the lock.

## Sensors

### Kernel-File ETW (primary attribution)

A real-time session named `Epicurus-Sensor` (configurable) enables two providers:

| Provider | GUID | Keywords | Events used |
|---|---|---|---|
| Microsoft-Windows-Kernel-File | `edd08927-9cc4-4e65-b970-c2560fb5c289` | `CREATE` 0x80, `DELETE_PATH` 0x400, `RENAME_SETLINK_PATH` 0x800 | 12 Create, 26 DeletePath, 27 RenamePath |
| Microsoft-Windows-Kernel-Process | `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` | `PROCESS` 0x10 | 1 ProcessStart, 2 ProcessStop |

These values come from the provider manifests (`wevtutil gp Microsoft-Windows-Kernel-File /ge /gm`). The Create event carries keywords `0xa0` (`FILEIO|CREATE`), so enabling only `CREATE` delivers it without the very high-volume `FILEIO` set. `READ` (0x100) is deliberately not enabled: it multiplies volume and raises the risk of buffer loss, and an open is already the signal.

- **Decoding.** Field layouts differ between event versions (ProcessStart has v0–v3), so fields are decoded *by name* from TDH metadata (`TdhGetEventInformation`). The metadata is cached per (provider, id, version) and the payload is walked sequentially. Hard-coded offsets are not used.
- **Filtering.** The NT path (`\Device\HarddiskVolumeN\...`) is normalized to a DOS path with a `QueryDosDeviceW` table (refreshed when an unknown device appears), lower-cased and looked up in a hash set of decoy paths. Opens of real credential stores (browser profiles, `.ssh`, `.aws`, wallets...) go into a bounded per-PID cache that triage reads as "other sensitive paths opened".
- **Session hygiene.** On start a stale session with the same name, left by a crash, is stopped. `ControlTraceW(QUERY)` reports `EventsLost`/`RealTimeBuffersLost`; increases are logged (event 1004) and shown in `status` and `doctor`. If the consumer thread dies (for example someone stops the session), the engine logs it and restarts ETW, or falls back to auditing.
- **Latency.** The flush timer is 1 s (the minimum). Every oplock break additionally calls `ControlTraceW(FLUSH)`, so the attributing Create event arrives immediately instead of at the next timer tick.

### Oplock tripwire (early warning, independent of ETW)

Each decoy is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` and `FILE_FLAG_OVERLAPPED`. An oplock is requested with `FSCTL_REQUEST_OPLOCK`, and completions arrive on an I/O completion port.

**Sharing semantics and the choice of level.**

- Because our handle shares read, write and delete, it never causes a sharing violation for anyone, including deletes and renames.
- A **Read-Handle (RH)** oplock (`OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`) breaks on writes, deletes, renames and share-mode conflicts, but *not* on a plain read-only open: several openers can each hold RH. A stealer that only reads would not trip it.
- Epicurus therefore first requests **Read-Write-Handle (RWH)**, which is RH plus `OPLOCK_LEVEL_CACHE_WRITE`. RWH is exclusive and breaks on any data-access open by another oplock key, including read-only opens. Attribute-only opens (Explorer listing a folder, `GetFileAttributes`) do not break it, which keeps noise down. The unit test `read_only_open_by_another_handle_breaks_the_oplock_without_blocking` demonstrates this on NTFS.
- **Never blocking.** The opener's `CreateFile` waits until the break is acknowledged. Epicurus records the precise time (`GetSystemTimePreciseAsFileTime`) and acknowledges at once by closing its handle, so the delay the opener sees is microseconds.
- **Re-arming.** RWH can only be granted while nobody else has the file open. After a break, re-arming waits 300 ms and then retries with exponential backoff. After three refusals (say, an indexer or scanner holding the file) it settles for RH until the next break. `doctor` reports how many decoys hold RWH versus RH.
- **Our own access.** Re-arming and hashing open decoys too. Those breaks are suppressed per path for a short window, and the ETW consumer drops events from the service's own PID.

**Correlation.** A break waits up to `correlation_window_ms` (3 s by default) for an ETW Create or 4663 event on the same path. A match contributes the earlier, precise timestamp to the incident timeline. A break that stays unattributed is logged as a touch (event 2030). Two or more unattributed breaks on different decoys within the sweep window raise an incident without a process, because that pattern suggests the file sensor is being blinded.

### Process table

Kernel-Process start/stop events plus a startup Toolhelp snapshot maintain entries keyed by **PID and creation time**:

- a recycled PID never inherits another process's identity (a new start for the same PID closes the old entry);
- lookups ask "which process held PID *p* at time *t*", with 2 s slack;
- exited processes are kept for 10 minutes, so a stealer that sweeps and exits is still attributed with image, parent, command line, user and integrity level (captured at start while it was alive);
- parent chains require the parent to be older than the child.

### Integrity watcher

`ReadDirectoryChangesW` (overlapped, one IOCP thread) on every directory containing decoys watches file name, size, last-write, attribute and security changes. Removed, renamed and modified events for decoy files are reported. A buffer overflow re-verifies every file in the directory, and losing the directory handle (the directory was deleted) reports every decoy missing from it. A "modified" event is confirmed by re-hashing; metadata-only changes are ignored. Each confirmed change is logged (event 2010), alerted, and removed from the manifest: a modified decoy is no longer ours to delete. It is then re-planted after a 2 s quiet period if `auto_replant` is on. A modified file left in place is treated as foreign from then on, so re-planting picks an alternate location.

### Degraded fallback: SACL + Security 4663

If the ETW session cannot start (session limit, policy), or `sensor.mode = "audit"`:

1. the "File System" audit subcategory (`0cce921d-69ae-11d9-bed3-505054503030`) is switched on for success with `AuditSetSystemPolicy`; the previous value is saved and restored by `uninstall`;
2. every decoy gets the SACL `S:(AU;SA;0x10007;;;WD)`: audit successful read data, write data, append and delete by Everyone;
3. `EvtSubscribe` on the Security channel with `*[System[(EventID=4663)]]` delivers access events. The rendered XML yields `ProcessId`, `ProcessName`, `ObjectName` and `AccessMask`, and `ReadData` (0x1) sets the "read data" score bit.

Trade-offs: Security log delivery adds latency, Group Policy can override the subcategory, and an administrator can clear the log. `doctor` and `status` show which mode is active, and the protection state is "Degraded" in audit mode.

## Triage

For a touch, the engine resolves the process from the table, enriches it if needed and builds a `ProcessProfile`:

- the image path from the live process if its creation time matches the table entry; otherwise the process is marked exited and only recorded data is used;
- SHA-256, size and creation time of the image;
- Authenticode via `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, revocation off, cache-only URL retrieval, so triage is fast and offline), with a fallback to catalog signatures (`CryptCATAdmin*`); most inbox Windows binaries are catalog-signed. The leaf-first signer chain comes from `WTHelperGetProvSignerFromChain`;
- command line (`ProcessCommandLineInformation`), user and SID, integrity level;
- location classification: `%TEMP%`/Downloads/`C:\Windows\Temp`, other user-writable locations, or protected locations;
- TCP/UDP endpoints (`GetExtendedTcpTable`/`GetExtendedUdpTable`, v4 and v6) and loaded modules;
- the protection check (below).

The allowlist is consulted with the signer, path and hash before an incident is created.

## Scoring

`epicurus_core::scoring::score` is a pure function; every contribution is a `Reason { code, points, detail }`:

| Code | Points | When |
|---|---|---|
| `decoy_touched` | +40 | always |
| `multiple_decoys` | +8 per extra decoy (max +24) | more than one distinct decoy |
| `two_categories` | +15 | exactly two categories |
| `category_sweep` | floor to 90 | ≥3 categories within the sweep window |
| `read_data` | +5 | data read (audit mode) |
| `destructive` | +15 | delete, rename or modify |
| `unsigned` / `bad_signature` / `trusted_signature` | +15 / +20 / −20 | signature verdict |
| `temp_or_downloads` / `user_writable_dir` | +15 / +10 | image location |
| `new_image` | +10 | image created < 24 h ago |
| `real_secrets_opened` | +10 | other real credential stores opened |
| `network` | +5 | non-listening connections |
| `script_parent` | +5 | parent is PowerShell, cmd, wscript, mshta, rundll32, … |

Bands: info 0–19, low 20–39, medium 40–59, high 60–79, critical 80–100. Touches from one process (PID + start time) accumulate into one incident and are re-scored on each touch. An escalation re-alerts and can trigger containment.

## Containment

The policy maps severity to `observe`, `alert` or `suspend` (default: suspend for high and critical).

- **Suspend tree.** `NtSuspendProcess` on the root first (so it cannot spawn more), then on every descendant from a fresh Toolhelp snapshot (children must be younger than their parent), then a second pass for children created meanwhile. Each handle is checked against the recorded creation time, so a recycled PID is refused.
- **Never contained:** PID 0/4, System, smss, csrss, wininit, services, lsass, winlogon, Registry, Memory Compression, Secure System, LsaIso, Epicurus itself, any process with a protection level (`ProcessProtectionLevelInfo` ≠ none, i.e. PPL), and processes marked critical (`IsProcessCritical`). For these Epicurus only alerts.
- **User actions:** kill tree (`TerminateProcess` descendants first), resume, quarantine (kill, move the image to `quarantine\<sha256>.quarantine` with the DACL `D:P(D;;FX;;;WD)(A;;FR;;;SY)(A;;FR;;;BA)` plus a JSON sidecar; files under `%SystemRoot%` are refused), block network (an outbound block rule for the image via `INetFwPolicy2`, group "Epicurus", removed on uninstall), allowlist (signer + exact path if validly signed, otherwise SHA-256; then resume), dismiss.
- **Minidump** (`MiniDumpWriteDump`) of suspended processes only if `policy.minidump = true`. It is off by default because dumps are large and contain whatever the process had already read.

## Planting safety

`epicurus_core::plan::Planner` decides; `epicurus_core::plant` executes:

- `CREATE_NEW` (`create_new(true)`) makes "does it exist?" and "create it" one atomic step. If anything appears between planning and planting, the create fails with a safety error and the foreign file is untouched.
- Missing parent directories are created one level at a time and recorded, so exactly those directories, and only if empty, are removed on unplant.
- `installed_if` excludes the real tool's location; `fresh_dirs` rejects a target inside a directory (decoy browser profile, decoy project, SSH subfolder) that already exists and is not Epicurus's.
- Targets inside sync roots (OneDrive from the user's registry hive and environment, Dropbox `info.json`, Google Drive, iCloud, Box) or git working trees are rejected, and so is any target outside the protected profile.
- Owner: the protected user (`SetNamedSecurityInfoW`, `SeRestorePrivilege`), so a decoy owned by Administrators does not stand out.
- Timestamps (created, modified, accessed) and sizes are backdated and varied deterministically from the per-install seed (HMAC-SHA256 stream). The same machine re-plants the same layout; different machines differ.
- Unplant deletes a file only if its SHA-256 still matches the manifest.

## Storage

SQLite in WAL mode (`epicurus.db`): `kv` (install seed, saved audit policy, firewall rule names), `decoys` (manifest; paths compared case-insensitively), `created_dirs`, `incidents` (JSON document plus indexed columns), `touch_log` and `events` (pruned after 30 days).

## Logging

`tracing` writes daily rolling files (14 kept): `%ProgramData%\Epicurus\logs\service.*.log` and `cli.*.log` for elevated commands; unprivileged UI processes use `%LOCALAPPDATA%\Epicurus\logs\ui.*.log`. Set `EPICURUS_LOG` (an `EnvFilter` directive) to change verbosity.

## Dependency notes

- **ETW without `ferrisetw`.** The ETW consumer is written directly against the official `windows` crate (`StartTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`, TDH) instead of `ferrisetw`. `ferrisetw`'s last release (1.2.0) dates from 2024 and pins an old `windows` version, and the project's rule is to avoid unmaintained crates (enforced by `cargo deny` with `unmaintained = "all"`). The consumer (`etw.rs`, about 850 lines including tests) is covered by decoder unit tests and the elevated integration test.
- **TLS.** `reqwest` is built with `rustls-no-provider` and the service installs the `ring` crypto provider at startup. No OpenSSL or native-tls (banned in `deny.toml`). Certificates are verified with `rustls-platform-verifier`, i.e. against the Windows certificate store.
- **Errors.** Library crates use typed `thiserror` errors (`epicurus_core::Error`, `SensorError`, `ServiceError`, `UiError`); only the `epicurus.exe` binary uses `anyhow` to format messages for the terminal.
