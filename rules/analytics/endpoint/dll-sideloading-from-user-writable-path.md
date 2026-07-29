---
id: dll-sideloading-from-user-writable-path
title: DLL Sideloading - Non-Microsoft DLL Dropped to AppData/ProgramData
tactic: Defense Evasion, Persistence
technique: T1574.002
sub_technique_name: Hijack Execution Flow - DLL Side-Loading
severity: medium
confidence: low
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceFileEvents]
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
  id: d109bc82-d6b7-41c5-9b66-0dea5bfbfe00
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [DefenseEvasion, Persistence]
  relevantTechniques: [T1574.002]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: File
      fieldMappings:
        - identifier: Name
          columnName: FileName
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
last_reviewed: "2026-07-29"
---

# DLL Sideloading - Non-Microsoft DLL Dropped to AppData/ProgramData

## Summary
Detects a `.dll` file dropped into `ProgramData`, `AppData\Local`, or
`AppData\Roaming` by a process that isn't Microsoft/Windows Defender —
the staging pattern for DLL side-loading, where a malicious DLL is
placed alongside (or in the search path of) a legitimate signed binary
so the legitimate binary loads it instead of the real library.

## Hypothesis
Legitimate application updates and installs from trusted vendors
predominantly write DLLs to `Program Files` or a vendor-signed install
directory, not directly to a user-writable temp-adjacent path like
`AppData\Local`. A non-Microsoft process writing a `.dll` into exactly
these paths is consistent with malware staging its side-loaded payload
next to a legitimate binary it plans to abuse — a pattern this rule
targets by drop location and originating process rather than by trying
to detect the sideloading itself, since the load event is
indistinguishable from a normal DLL load once it happens.

## Threat intelligence context
Directly informed by IR-2026-004 (this repo's own incident): both
`vaelix.exe` and `Ditto.exe` were dropped to exactly this location
pattern (`AppData\Local\Ditto\`), with `Ditto.exe`'s drop bringing 6
supporting DLLs alongside it in the same folder — a real Ditto install
also ships some of these files, which is precisely what made the
repurposed copy hard to distinguish from a genuine one without
hash/publisher verification. Also generalized from Wizard Cyber's
published "Cross-tenant Helpdesk Impersonation" technique profile,
which documents this same staging pattern as a recurring stage in the
broader attack family IR-2026-004 belongs to.

## Query

**Sentinel / Defender XDR**
```kusto
let lookback = 1d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where FolderPath has_any (@"\ProgramData\", @"\AppData\Local\", @"\AppData\Roaming\")
| where FileName endswith ".dll"
| where InitiatingProcessFileName !has "Microsoft" and InitiatingProcessFileName !has "Windows Defender"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName,
          InitiatingProcessCommandLine, SHA256
| order by Timestamp asc
```
Same query works unchanged in Defender XDR advanced hunting and
Sentinel — `DeviceFileEvents` is a shared MDE-sourced table in both.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Defense Evasion, Persistence — T1574.002 |
| Entity mappings | `Host.Name = DeviceName` · `File.Name = FileName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
Multiple `.dll` drops to the same `FolderPath` in a short window,
especially alongside a same-folder `.exe` drop from the same
`InitiatingProcessFileName` (classic installer-driven side-load
staging — matches the confirmed IR-2026-004 pattern of an MSI dropping
an EXE plus its supporting DLLs together). Pull `SHA256` and check
publisher/signature status before assuming malicious — this rule is
intentionally broad and leans on triage, not standalone certainty.

## False positive notes
This is the noisiest rule in the repo by design — legitimate software
updaters (browsers, Electron apps, many SaaS desktop clients) routinely
drop DLLs to `AppData\Local` as part of normal auto-update behavior,
and `InitiatingProcessFileName !has "Microsoft"` only filters the most
obvious case. Expect significant tuning work: build an
`ApprovedUpdaterProcesses` allowlist (Chrome/Edge/Slack/Teams/Zoom
updater processes, common Electron auto-updaters) before relying on
this in production, or scope it further to specific high-value device
groups first.

## Detection blind spots
`InitiatingProcessFileName !has "Microsoft"` is a weak filter — it's a
substring check against the process name/path, not a signature or
publisher validation, so a malicious binary named to include "Microsoft"
or one that spoofs the publisher field (as `Ditto.exe` itself did in
IR-2026-004, spoofing publisher "Microsoft") can evade this exclusion
entirely, or conversely get incorrectly excluded if it happens to match.
A more robust version would check `InitiatingProcessSignerType`/
`InitiatingProcessSHA256` against a real Microsoft-signed catalog rather
than a name substring — this simpler version is a starting point, not a
finished control.

## Validation
No confirmed Atomic Red Team test identified — DLL side-loading staging
is highly payload-specific and most ART tests simulate the load itself
(via a specific vulnerable binary) rather than this generic drop
pattern. Validate manually: copy a non-Microsoft-signed `.dll` into
`%LOCALAPPDATA%\TestApp\` via a non-Microsoft process (e.g.
`powershell.exe Copy-Item`) and confirm the rule fires, then tune the
`InitiatingProcessFileName` exclusion against real update-tool traffic
in this environment before enabling broadly.

## References
- MITRE ATT&CK: [T1574.002](https://attack.mitre.org/techniques/T1574/002/) (Hijack Execution Flow: DLL Side-Loading)
- Source: Wizard Cyber — Cross-tenant Helpdesk Impersonation technique profile
