---
id: inhibit-system-recovery-shadow-copy-deletion
title: Inhibit System Recovery - Shadow Copy / Backup Deletion (Ransomware Precursor)
tactic: Impact
technique: T1490
sub_technique_name: Inhibit System Recovery
severity: high
confidence: high
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceProcessEvents]
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references: []
validated:
  atomic_test: T1490-1
  atomic_test_url: "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-1-windows---delete-volume-shadow-copies"
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: 4a45e6bf-152f-4c65-97ee-1f675b0192ff
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [Impact]
  relevantTechniques: [T1490]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: AccountName
    - entityType: Process
      fieldMappings:
        - identifier: CommandLine
          columnName: ProcessCommandLine
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

# Inhibit System Recovery - Shadow Copy / Backup Deletion (Ransomware Precursor)

## Summary
Detects command-line invocations that delete or disable Windows shadow
copies, backups, and recovery options — the near-universal precursor
step before ransomware detonation, executed to prevent victim
restoration. Matches `vssadmin`/`wmic` shadow-copy deletion, `wbadmin`
catalog/backup deletion, `bcdedit` recovery-disabling flags, and
PowerShell WMI/CIM shadow-copy removal.

## Hypothesis
Deleting shadow copies or backup catalogs has almost no legitimate
day-to-day business purpose outside scheduled backup software pruning
its own storage — an interactive or scripted invocation of these exact
commands is one of the highest-confidence precursor signals for
ransomware available, since nearly every major ransomware family
performs this step before or during encryption to block recovery.

## Threat intelligence context
No named actor, malware family, or campaign — this targets a technique
common across essentially all ransomware families, not one specific
threat.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let recoveryTamperPatterns = dynamic([
    "vssadmin delete shadows", "vssadmin.exe delete shadows", "vssadmin resize shadowstorage",
    "wmic shadowcopy delete", "wmic.exe shadowcopy delete",
    "wbadmin delete catalog", "wbadmin.exe delete catalog", "wbadmin delete backup", "wbadmin.exe delete backup",
    "bcdedit /set", "bcdedit.exe /set",
    "get-wmiobject win32_shadowcopy", "get-ciminstance win32_shadowcopy"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (recoveryTamperPatterns)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, ReportId
| order by Timestamp desc
```
(Same query works unchanged in both — this uses only shared
`DeviceProcessEvents` schema fields.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Impact — T1490 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` · `Process.CommandLine = ProcessCommandLine` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` running one of the flagged commands.
Treat as high-priority regardless of what else is happening on the
host — this is a precursor step, and the window to contain before
encryption begins is short.

## False positive notes
Legitimate backup software (Veeam, Azure Backup agent, Windows Server
Backup scheduled jobs) resizing/pruning shadow storage as part of
normal operation, and admins intentionally disabling System Restore on
VM templates during imaging, are the expected sources of noise.
Exclude the known backup service accounts/processes rather than
removing the command patterns.

## Detection blind spots
Only catches command-line invocation via the listed binaries — a
ransomware strain that deletes shadow copies via direct WMI/COM API
calls from a compiled binary (bypassing `vssadmin.exe`/`wmic.exe`
entirely) produces no command-line signal here. Also relies on process
command-line visibility; heavily obfuscated or base64-encoded
PowerShell invocations of the same WMI/CIM cmdlets could evade the
plain-text pattern match.

## Validation
Matching Atomic Red Team test identified: [T1490 Atomic Test #1 — Windows - Delete Volume Shadow Copies](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-1-windows---delete-volume-shadow-copies)
(`vssadmin.exe delete shadows /all /quiet`). Not yet executed against a
lab device — running it and confirming the rule fires is the next
step.

## References
- MITRE ATT&CK: [T1490](https://attack.mitre.org/techniques/T1490/) (Inhibit System Recovery)
