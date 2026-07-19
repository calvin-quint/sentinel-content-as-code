---
id: clickfix-paste-and-run-detection
title: ClickFix / Paste-and-Run Detection
tactic: Execution
technique: T1204.004
sub_technique_name: User Execution - Malicious Copy and Paste
severity: high
confidence: high
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceRegistryEvents, DeviceProcessEvents]
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references: []
validated:
  atomic_test: null
  atomic_test_url: null
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: 1383fc8e-605e-402a-985c-7d89fd9059f8
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [Execution]
  relevantTechniques: [T1204.004]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: AccountName
  incidentConfiguration:
    createIncident: true
    groupingConfiguration:
      enabled: true
      reopenClosedIncident: false
      lookbackDuration: PT5H
      matchingMethod: AllEntities
  eventGroupingSettings:
    aggregationKind: SingleAlert
owner: calvin
last_reviewed: "2026-07-19"
---

# ClickFix / Paste-and-Run Detection

## Summary
Detects the ClickFix social engineering pattern — a user is lured by a
fake CAPTCHA/"verify you are human" page into pressing Win+R (or
opening a terminal) and pasting an attacker-supplied command, which
`explorer.exe` then spawns via `cmd.exe`, `powershell.exe`, or
`mshta.exe`. Correlates a Run-dialog (`RunMRU`) registry write with a
suspicious child process launch from `explorer.exe` within a short
window for higher fidelity than command-line matching alone.

## Hypothesis
The ClickFix technique has a distinctive two-step shape at the OS
level: a `RunMRU` registry write (the fingerprint of using Win+R) is
followed within a couple of minutes by `explorer.exe` spawning a shell
or script host running a command that matches known download-cradle or
obfuscation patterns. Neither a `RunMRU` write nor an explorer-spawned
shell is unusual alone — technical users use Run constantly — but the
combination plus a suspicious command line is specific to a user being
walked through pasting an attacker's command.

## Threat intelligence context
No named actor, malware family, or campaign — ClickFix is a widely
used social-engineering delivery technique across many different
malware families and campaigns, not tied to one actor.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let suspiciousCmdPatterns = dynamic([
    "iwr ", "invoke-webrequest", "irm ", "invoke-restmethod", "curl ", "wget ",
    "certutil -urlcache", "certutil.exe -urlcache", "bitsadmin /transfer",
    "-w hidden", "-windowstyle hidden", "-enc ", "-encodedcommand",
    "iex(", "iex (", "invoke-expression", "downloadstring", "downloadfile",
    "mshta http", "mshta.exe http"
]);
// Step 1: Run-dialog usage - writing to RunMRU is the fingerprint of Win+R paste-and-execute
let RunDialogUsage =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    | where ActionType == "RegistryValueSet"
    | project DeviceId, DeviceName, RunTimestamp = Timestamp, RunValue = RegistryValueData;
// Step 2: Suspicious shell/script processes spawned directly by explorer.exe
let SuspiciousExplorerChildren =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessFileName =~ "explorer.exe"
    | where FileName has_any ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe")
    | where ProcessCommandLine has_any (suspiciousCmdPatterns)
    | project DeviceId, DeviceName, ProcTimestamp = Timestamp, AccountName, FileName,
              ProcessCommandLine, InitiatingProcessFileName, ReportId;
// Step 3: Join - RunMRU write followed within 2 minutes by the suspicious process launch
RunDialogUsage
| join kind=inner (SuspiciousExplorerChildren) on DeviceId
| where ProcTimestamp - RunTimestamp between (0min .. 2min)
| project ProcTimestamp, DeviceName, AccountName, RunValue, FileName,
          ProcessCommandLine, InitiatingProcessFileName, ReportId
| order by ProcTimestamp desc
```
(Same query works unchanged in both — this uses only shared
`DeviceRegistryEvents`/`DeviceProcessEvents` schema fields.) A lower-
fidelity fallback that drops the `RunMRU` correlation requirement
(useful if that telemetry is inconsistent, but noisier) is available
commented-out in the original `.kql`.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Execution — T1204.004 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` with a `RunValue` (the pasted command,
visible in `RunMRU`) followed within 2 minutes by `explorer.exe`
spawning `FileName` with a matching suspicious `ProcessCommandLine`.
The `RunValue` itself is often the clearest evidence of what the user
was tricked into pasting.

## False positive notes
IT staff quick-launching tools via the Run dialog (`mmc`,
`services.msc`, etc.) are the main source of noise — tune the
`FileName` allowlist and command-line exclusions for known admin
workflows rather than excluding `RunMRU` correlation broadly.

## Detection blind spots
Only catches the shell/script-host launch path from `explorer.exe`
specifically — a variant where the user is directed to open a terminal
application directly (Windows Terminal, a pinned PowerShell shortcut)
rather than using Win+R produces no `RunMRU` write and evades the
correlated detection (falling back to the noisier standalone pattern
only). The `suspiciousCmdPatterns` list is also a fixed set of known
download-cradle/obfuscation strings — a command that doesn't match any
of them (e.g., a raw base64 blob decoded by a script rather than
inline `-enc`) could evade the command-line filter.

## Validation
No confirmed Atomic Red Team test identified — ClickFix is a relatively
recent, rapidly evolving social-engineering technique (T1204.004); a
dedicated ART atomic test wasn't confirmed at time of writing. Validate
manually: simulate the Win+R paste-and-run flow on a lab device (write
to `RunMRU`, then have `explorer.exe` spawn `powershell.exe` with a
command matching one of the listed patterns) and confirm the rule
fires.

## References
- MITRE ATT&CK: [T1204.004](https://attack.mitre.org/techniques/T1204/004/) (User Execution: Malicious Copy and Paste)
