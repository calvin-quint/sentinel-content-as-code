---
id: impair-defenses-edr-av-tamper
title: Impair Defenses - EDR/AV Tamper Attempt
tactic: Defense Evasion
technique: T1562.001
sub_technique_name: Impair Defenses - Disable or Modify Tools
severity: high
confidence: high
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceProcessEvents, DeviceRegistryEvents]
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references: []
validated:
  atomic_test: T1562.001-19
  atomic_test_url: "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md#atomic-test-19-tamper-with-windows-defender-atp-powershell"
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: 10232763-90dc-4051-804e-efc07283ce7a
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [DefenseEvasion]
  relevantTechniques: [T1562.001]
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

# Impair Defenses - EDR/AV Tamper Attempt

## Summary
Detects attempts to disable, stop, or weaken Microsoft Defender/EDR
protections — service stops, PowerShell cmdlets disabling real-time
protection or adding broad scan exclusions, and registry writes to the
Defender tamper-protection and policy keys. This directly threatens the
detection pipeline itself, so treat any hit as high priority regardless
of what else is happening on the host.

## Hypothesis
An attempt to disable or exclude from Defender scanning, or to stop the
`WinDefend` service, has essentially no legitimate justification outside
approved security-tooling administration — and because a successful
tamper attempt blinds every *other* detection on this repo running
against that host, this rule treats any hit as maximum priority
regardless of correlated activity, rather than waiting for a second
signal to corroborate it.

## Threat intelligence context
No named actor, malware family, or campaign — a generic defense-
impairment detection common across most intrusion types, including as a
frequent ransomware precursor.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let tamperCmdPatterns = dynamic([
    "set-mppreference -disablerealtimemonitoring", "set-mppreference -disableioavprotection",
    "set-mppreference -disablebehaviormonitoring", "set-mppreference -disablescriptscanning",
    "add-mppreference -exclusionpath", "add-mppreference -exclusionprocess", "add-mppreference -exclusionextension",
    "sc stop windefend", "sc.exe stop windefend", "sc config windefend start= disabled", "sc.exe config windefend start= disabled",
    "net stop windefend", "net.exe stop windefend",
    "taskkill /im msmpeng.exe", "taskkill /f /im msmpeng.exe", "taskkill.exe /im msmpeng.exe"
]);
let TamperProcesses =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "sc.exe", "net.exe", "taskkill.exe")
    | where ProcessCommandLine has_any (tamperCmdPatterns)
    | project DeviceId, DeviceName, Timestamp, AccountName, FileName, ProcessCommandLine,
              InitiatingProcessFileName, ReportId, Vector = "ProcessCommand";

let tamperRegistryPaths = dynamic([
    @"Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
    @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring",
    @"Software\Microsoft\Windows Defender\Features\TamperProtection",
    @"Software\Policies\Microsoft\Windows Defender\Exclusions"
]);
let TamperRegistry =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any (tamperRegistryPaths)
    | project DeviceId, DeviceName, Timestamp, AccountName, RegistryKey, RegistryValueData,
              InitiatingProcessFileName, ReportId, Vector = "RegistryTamper";

TamperProcesses
| union TamperRegistry
| summarize FirstSeen = min(Timestamp), Vectors = make_set(Vector), HitCount = count()
    by DeviceName, AccountName
| order by FirstSeen desc
```
(Same query works unchanged in both — this uses only shared
`DeviceProcessEvents`/`DeviceRegistryEvents` schema fields.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Defense Evasion — T1562.001 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` with a tamper attempt via either
`ProcessCommand` or `RegistryTamper` vector (or both — `Vectors` shows
which). Escalate immediately; if the tamper attempt succeeded, this
host's other telemetry may already be unreliable.

## False positive notes
Legitimate security-tooling administration by the EDR/AV team pushing
config changes via approved deployment tooling is the expected source
of noise. Exclude the Intune/MDM management accounts and Defender
configuration management service accounts explicitly.

## Detection blind spots
Only catches the listed command patterns and registry paths — Defender
tamper via the Windows Security Center API directly (bypassing both
PowerShell cmdlets and the listed registry keys), or via a compiled
binary calling the underlying COM/WMI interfaces, produces no signal
here. If the tamper attempt succeeds *before* this query's next
scheduled run, MDE's own telemetry pipeline for that host may already
be degraded — this rule can't detect a tamper that also disables its
own data source.

## Validation
Matching Atomic Red Team test identified: [T1562.001 Atomic Test #19 — Tamper with Windows Defender ATP PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md#atomic-test-19-tamper-with-windows-defender-atp-powershell)
(`Set-MpPreference -DisableRealtimeMonitoring 1` and related). Not yet
executed against a lab device — running it and confirming the rule
fires is the next step.

## References
- MITRE ATT&CK: [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Impair Defenses: Disable or Modify Tools)
