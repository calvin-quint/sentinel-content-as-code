---
id: reflective-code-loading-memory-only-module
title: Reflective Code Loading / Fileless In-Memory Execution Detection
tactic: Defense Evasion, Execution, Privilege Escalation
technique: T1620, T1055, T1059.001, T1027.011
sub_technique_name: Reflective Code Loading
severity: high
confidence: medium
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents]
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
  id: 2307a1de-4819-4bb8-837c-f377ac7ff089
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [DefenseEvasion, Execution, PrivilegeEscalation]
  relevantTechniques: [T1620, T1055, T1059.001, T1027.011]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: AccountName
    - entityType: URL
      fieldMappings:
        - identifier: Url
          columnName: RemoteUrl
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

# Reflective Code Loading / Fileless In-Memory Execution Detection

## Summary
Detects code downloaded and executed directly in memory without ever
being written to disk — the classic "download cradle" pattern (`IEX` +
`DownloadString`, `Reflection.Assembly` load, `Add-Type` from a remote
byte array). Combines AMSI-based content detection with command-line
pattern matching, then correlates against `DeviceFileEvents` to confirm
no corresponding executable/script file was written — the absence of a
file write is the actual fingerprint of this technique, not any single
indicator alone.

## Hypothesis
Legitimate PowerShell automation that downloads and executes code
almost always writes an intermediate file (a downloaded installer,
script, or module) before running it, or is a known, allowlisted CI/CD
pattern. A process matching download-cradle command-line patterns, with
a correlated outbound network connection, and *no* corresponding file
write anywhere in the same window, is specifically the fileless-
execution fingerprint — the absence of the expected artifact is what
this rule keys on, not just the suspicious command line by itself.

## Threat intelligence context
No named actor, malware family, or campaign — reflective/fileless
loading is a widely reused defense-evasion technique across a broad
range of malware loaders and post-exploitation frameworks, not tied to
one actor.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let downloadCradlePatterns = dynamic([
    "downloadstring", "downloaddata", "downloadfile",
    "net.webclient", "invoke-webrequest", "invoke-restmethod",
    "iex(", "iex (", "invoke-expression",
    "[system.reflection.assembly]::load", "reflection.assembly]::load",
    "frombase64string", "add-type -typedefinition",
    "[runtime.interopservices", "virtualalloc", "createthread"
]);

// Step 1: AMSI-flagged in-memory script content (highest fidelity signal, if AMSI events present)
let AmsiHits =
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType has "Amsi"
    | project DeviceId, DeviceName, Timestamp, ActionType, AccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId;

// Step 2: Process command lines matching download-cradle / in-memory load patterns
let CradleProcesses =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe")
    | where ProcessCommandLine has_any (downloadCradlePatterns)
    | project DeviceId, DeviceName, ProcTimestamp = Timestamp, AccountName, FileName,
              ProcessCommandLine, ProcessId = InitiatingProcessId, ReportId;

// Step 3: Network connection from the same process around the same time (confirms the download leg)
let CorrelatedNetwork =
    CradleProcesses
    | join kind=inner (
        DeviceNetworkEvents
        | where Timestamp > ago(lookback)
        | project DeviceId, NetTimestamp = Timestamp, RemoteUrl, RemoteIP, InitiatingProcessId
    ) on DeviceId
    | where NetTimestamp between ((ProcTimestamp - 30s) .. (ProcTimestamp + 2m))
    | project DeviceId, DeviceName, ProcTimestamp, AccountName, FileName,
              ProcessCommandLine, RemoteUrl, RemoteIP, ReportId;

// Step 4: Anti-join against DeviceFileEvents - no matching executable/script write in the same window
// confirms the payload never touched disk (the core fileless fingerprint)
let FileWritesInWindow =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "FileCreated"
    | where FileName has_any (".exe", ".dll", ".ps1", ".vbs", ".js", ".hta")
    | project DeviceId, FileWriteTimestamp = Timestamp;

CorrelatedNetwork
| join kind=leftanti (FileWritesInWindow) on DeviceId
| union (AmsiHits | project DeviceId, DeviceName, ProcTimestamp = Timestamp, AccountName,
          FileName = InitiatingProcessFileName, ProcessCommandLine = InitiatingProcessCommandLine,
          RemoteUrl = "", RemoteIP = "", ReportId)
| summarize FirstSeen = min(ProcTimestamp), HitCount = count() by DeviceName, AccountName, FileName, ProcessCommandLine, RemoteUrl
| order by FirstSeen desc
```
(Same query works unchanged in both — this uses only shared
`DeviceEvents`/`DeviceProcessEvents`/`DeviceNetworkEvents`/
`DeviceFileEvents` schema fields.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Defense Evasion, Execution, Privilege Escalation — T1620, T1055, T1059.001, T1027.011 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` · `URL.Url = RemoteUrl` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` with a download-cradle command line, a
correlated `RemoteUrl`/`RemoteIP`, and no matching file write in the
same window — or an `AmsiHits` match, which is the highest-fidelity
standalone signal if AMSI telemetry is present. Pull `ProcessCommandLine`
in full; it usually reveals the second-stage payload's actual purpose.

## False positive notes
Legitimate DevOps/automation scripts using in-memory module loading
(e.g., PowerShell Gallery module imports via `Install-Module`
internals, some Chocolatey/Scoop installers) are the expected source of
noise. Baseline admin scripting patterns and exclude known-good signed
script hashes rather than removing pattern coverage broadly.

## Detection blind spots
The `FileWritesInWindow` anti-join only checks for a small set of
executable/script extensions — a payload written with a disguised or
missing extension, or one that immediately deletes itself after being
written, could still show as "fileless" here even though a file
transiently existed. AMSI coverage (`Step 1`) only helps if AMSI
providers are actually active and logging on the endpoint; a technique
that specifically bypasses AMSI (a known and actively developed evasion
category) produces no signal from that half of the rule, leaving only
the command-line + anti-join path.

## Validation
No confirmed Atomic Red Team test identified for this exact combined
AMSI + command-line + file-write-absence pattern — ART has scattered
coverage of individual sub-techniques (T1055 process injection, T1620
reflective loading) but a single test matching this rule's full
correlation logic wasn't confirmed. Validate manually: run a PowerShell
`IEX (New-Object Net.WebClient).DownloadString(...)` download-cradle
pattern on a lab device against a benign test payload and confirm the
rule fires with no corresponding file write.

## References
- MITRE ATT&CK: [T1620](https://attack.mitre.org/techniques/T1620/) (Reflective Code Loading), [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (PowerShell), [T1027.011](https://attack.mitre.org/techniques/T1027/011/) (Fileless Storage)
