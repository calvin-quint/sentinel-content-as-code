---
id: abuse-elevation-control-uac-bypass
title: Abuse Elevation Control Mechanism - UAC Bypass
tactic: Privilege Escalation, Defense Evasion
technique: T1548.002
sub_technique_name: Abuse Elevation Control Mechanism - Bypass User Account Control
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
  id: 1e8e5cdc-d6b9-4604-bc95-44fdb2d6c593
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [PrivilegeEscalation, DefenseEvasion]
  relevantTechniques: [T1548.002]
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

# Abuse Elevation Control Mechanism - UAC Bypass

## Summary
Detects the classic UAC bypass pattern abusing Windows binaries that
auto-elevate without a consent prompt (fodhelper, eventvwr,
computerdefaults, sdclt, slui, cmstp, wsreset). Two-stage detection:
(1) a registry write to the hijack paths these binaries read from
before elevating, followed by (2) the auto-elevate binary itself
spawning an unexpected child process (a shell) — which it never
legitimately does on its own. Either signal alone is weak; the pair
together is high-fidelity.

## Hypothesis
None of the listed auto-elevate binaries (fodhelper.exe, eventvwr.exe,
etc.) legitimately spawn a shell or script host as a child process
during normal operation — they exist to launch a specific management
UI, not `cmd.exe`/`powershell.exe`. A registry write to the exact hijack
path one of these binaries reads from, followed within 5 minutes by
that same binary spawning a shell, is a two-step chain with no
legitimate explanation other than a deliberate UAC bypass.

## Threat intelligence context
No named actor, malware family, or campaign — this targets the general
class of registry-hijack auto-elevate UAC bypass techniques, not one
specific threat.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let autoElevateBinaries = dynamic(["fodhelper.exe", "eventvwr.exe", "computerdefaults.exe",
                                    "sdclt.exe", "slui.exe", "cmstp.exe", "wsreset.exe", "changepk.exe"]);
let hijackRegistryPaths = dynamic([
    @"Software\Classes\ms-settings\Shell\Open\command",
    @"Software\Classes\mscfile\Shell\Open\command",
    @"Software\Classes\exefile\Shell\Open\command",
    @"Software\Classes\Folder\shell\open\command"
]);

// Stage 1: registry hijack of the path an auto-elevate binary will read
let RegistryHijack =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has_any (hijackRegistryPaths)
    | where RegistryKey has "command" // the default value under \command holds the hijacked launch string
    | project DeviceId, DeviceName, RegTimestamp = Timestamp, AccountName,
              RegistryKey, RegistryValueData, InitiatingProcessFileName, ReportId;

// Stage 2: the auto-elevate binary runs and spawns an unexpected child (shell/script host)
let AutoElevateChildSpawn =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessFileName in~ (autoElevateBinaries)
    | where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")
    | project DeviceId, DeviceName, ProcTimestamp = Timestamp, AccountName,
              AutoElevateBinary = InitiatingProcessFileName, SpawnedProcess = FileName,
              ProcessCommandLine, ReportId;

// Correlate: registry hijack followed within 5 minutes by the auto-elevate binary spawning a shell
RegistryHijack
| join kind=inner (AutoElevateChildSpawn) on DeviceId
| where ProcTimestamp - RegTimestamp between (0min .. 5min)
| project ProcTimestamp, DeviceName, AccountName, RegistryKey, RegistryValueData,
          AutoElevateBinary, SpawnedProcess, ProcessCommandLine, ReportId
| order by ProcTimestamp desc
```
(Same query works unchanged in both — this uses only shared
`DeviceRegistryEvents`/`DeviceProcessEvents` schema fields.) A
standalone fallback matching an auto-elevate binary spawning a shell
with no registry correlation (useful when registry auditing has gaps,
but noisier) is available commented-out in the original `.kql`.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Privilege Escalation, Defense Evasion — T1548.002 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` with `RegistryKey` matching a hijack path,
followed within 5 minutes by `AutoElevateBinary` spawning
`SpawnedProcess`. `ProcessCommandLine` on the spawned shell usually
reveals what the attacker did with the elevated context.

## False positive notes
Rare for the correlated (two-stage) version specifically — the
registry-only stage can fire on legitimate settings troubleshooting,
which is exactly why this rule requires the process-spawn correlation
before alerting rather than acting on Stage 1 alone.

## Detection blind spots
Only covers the 8 listed auto-elevate binaries and 4 hijack registry
paths — other known UAC-bypass techniques (COM handler hijacking,
DLL search-order hijacking of an auto-elevating binary, or newer
bypass methods not yet on this list) produce no signal. The 5-minute
correlation window also means a patient attacker who waits longer
between the registry write and triggering the elevated binary evades
the correlated detection (though may still surface via the noisier
standalone fallback).

## Validation
Atomic Red Team has extensive T1548.002 coverage, including dedicated
Fodhelper and Event Viewer bypass tests (Atomic Tests #1-#9 cover
Event Viewer, Fodhelper, ComputerDefaults, and sdclt variants) — see
[T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)
for the full list. Not yet executed against a lab device — running the
Fodhelper test specifically (it matches this rule's auto-elevate
binary list directly) and confirming both stages correlate is the next
step.

## References
- MITRE ATT&CK: [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Bypass User Account Control)
