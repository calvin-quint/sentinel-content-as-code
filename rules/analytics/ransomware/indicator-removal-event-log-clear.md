---
id: indicator-removal-event-log-clear
title: Indicator Removal - Windows Event Log Cleared
tactic: Defense Evasion
technique: T1070.001
sub_technique_name: Indicator Removal - Clear Windows Event Logs
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
  atomic_test: T1070.001-1
  atomic_test_url: "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md#atomic-test-1-clear-logs"
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: cb7454b5-60d1-4b8b-9efa-12b590e26c48
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
  relevantTechniques: [T1070.001]
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

# Indicator Removal - Windows Event Log Cleared

## Summary
Detects command-line invocation of the classic Windows event-log-
clearing utilities/cmdlets — `wevtutil cl`/`clear-log`, PowerShell
`Clear-EventLog`/`Remove-EventLog`, and the `wmic ntevent` clear path.
Nearly always a deliberate anti-forensics step taken immediately after
an intrusion to erase evidence, rarely a routine admin action outside
scheduled log rotation.

## Hypothesis
Clearing an entire Windows event log via command line is a rare,
deliberate action outside of scheduled maintenance windows — legitimate
log management almost always uses retention/rotation policies rather
than an ad-hoc `wevtutil cl` or `Clear-EventLog` invocation, so any
occurrence outside a known maintenance process is worth immediate
review.

## Threat intelligence context
No named actor, malware family, or campaign — a generic anti-forensics
detection used across nearly every intrusion type, including as a
common ransomware precursor/companion step.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let logClearPatterns = dynamic([
    "wevtutil cl", "wevtutil.exe cl", "wevtutil clear-log", "wevtutil.exe clear-log",
    "clear-eventlog", "remove-eventlog", "wmic ntevent"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("wevtutil.exe", "powershell.exe", "pwsh.exe", "wmic.exe")
| where ProcessCommandLine has_any (logClearPatterns)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, ReportId
| order by Timestamp desc
```
(Same query works unchanged in both — this uses only shared
`DeviceProcessEvents` schema fields.) A complementary native signal
using `SecurityEvent` Event ID 1102 ("The audit log was cleared") is
available as a commented-out fallback in the original `.kql` for
workspaces that also ingest that table via AMA/legacy agent.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Defense Evasion — T1070.001 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` running `wevtutil cl`, `Clear-EventLog`, or
similar. Check what other activity occurred on the host immediately
before the clear — this is almost always a cleanup step at the *end* of
an intrusion phase, so the interesting evidence is what happened just
prior.

## False positive notes
Scheduled log-rotation/maintenance scripts, or backup/imaging processes
that clear logs on a golden-image template before capture, are the
expected sources of noise. Exclude known maintenance windows/service
accounts rather than the command patterns themselves.

## Detection blind spots
Only catches command-line-driven clearing via the listed binaries — a
tool that clears logs via direct Windows Event Log API calls from a
compiled binary (not `wevtutil.exe`/PowerShell) produces no signal
here. Since MDE's own telemetry is itself dependent on the event log
pipeline being intact, an attacker who disables logging *before*
generating the clear command (rather than clearing after the fact)
could reduce what's captured in the first place — this rule only sees
what MDE recorded before any tampering took effect.

## Validation
Matching Atomic Red Team test identified: [T1070.001 Atomic Test #1 — Clear Logs](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md#atomic-test-1-clear-logs)
(`wevtutil cl #{log_name}`). Not yet executed against a lab device —
running it and confirming the rule fires is the next step.

## References
- MITRE ATT&CK: [T1070.001](https://attack.mitre.org/techniques/T1070/001/) (Indicator Removal: Clear Windows Event Logs)
