# Windows Event Log IDs

Epicurus writes to the **Application** log under the source **`Epicurus`**. `install` registers the source with `epicurus.exe` as its message file; the executable embeds a message table whose text is the event's insertion string, so Event Viewer and SIEM collectors show the full message. Event log writing can be disabled with `alerts.eventlog = false`.

| ID | Level | Meaning | Message contents |
|---|---|---|---|
| 1000 | Information | Service started | version |
| 1001 | Information | Service stopped | |
| 1002 | Information | Active file sensor mode | `etw`, `audit` or `none` |
| 1003 | Warning / Error | Sensor degraded or failed (ETW unavailable, fallback engaged, consumer stopped, IPC server failed, service failure) | reason |
| 1004 | Warning | ETW session lost events or real-time buffers | count since last check, total |
| 1010 | Information | Decoys planted | files planted, manifest size |
| 1011 | Information | Decoys removed | removed, kept (modified), remaining |
| 2000 | Information / Warning / Error | Incident created (Information for info, Warning for low/medium, Error for high/critical) | incident id, severity, score, simulation flag, image, PID, decoys, categories, signer, containment state |
| 2001 | as 2000 | Incident severity escalated | as 2000 |
| 2002 | Warning / Information | Containment action succeeded (policy suspension, or a user action) | incident id, action, PIDs |
| 2003 | Warning / Error | Containment action failed or refused (protected process) | incident id, reason |
| 2010 | Warning | A decoy was deleted, renamed or modified | decoy id, path, change |
| 2011 | Information | Decoys re-planted after an integrity change | decoy ids |
| 2020 | Information | An allowlisted process touched a decoy (rate-limited to once per image per hour) | image, PID, allowlist entry, decoy |
| 2030 | Warning | Oplock tripwire fired with no attributed process | decoy id |
| 3000 | Warning | Alert delivery failed | channel and error (never the URL) |
| 3001 | Information | Configuration changed over IPC (allowlist, alert channels, settings) | what changed |
| 9000 | Information | Test event from the dashboard "send test" button | |

Message text of 2000 (example):

```
Incident inc_3f9a0c1d2b4e5f60 [critical 95/100] (simulation): C:\Program Files\Epicurus\epicurus.exe (PID 4242) touched 5 decoy(s) in 4 categor(ies). Signer: unsigned. Suspended 1 process(es); awaiting your decision
```

## Collecting

PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Epicurus'; Id = 2000, 2001, 2002, 2003, 2010, 2030 }
```

Windows Event Forwarding / Sysmon-style subscriptions can select `*[System[Provider[@Name='Epicurus'] and (EventID>=2000 and EventID<3000)]]`.

## Stability

These IDs are part of the public interface. New IDs are added within the existing ranges (1000–1099 service and sensors, 2000–2099 detections and actions, 3000–3099 alerting and configuration, 9000–9009 tests); existing IDs do not change meaning.
