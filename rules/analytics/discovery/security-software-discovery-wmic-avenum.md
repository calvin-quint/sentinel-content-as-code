---
id: security-software-discovery-wmic-avenum
title: Security Software Discovery - WMIC AntiVirusProduct Enumeration
tactic: Discovery
technique: T1518.001
sub_technique_name: Security Software Discovery
severity: medium
confidence: medium
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
  atomic_test: null
  atomic_test_url: null
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: 757e8efe-22a7-4fd9-98c7-8cf8f5d33d38
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [Discovery]
  relevantTechniques: [T1518.001]
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
last_reviewed: "2026-07-29"
---

# Security Software Discovery - WMIC AntiVirusProduct Enumeration

## Summary
Detects `wmic.exe` invoked against the `SecurityCenter2` WMI namespace to
enumerate installed antivirus/EDR products — a standard pre-execution
fingerprinting step attackers use to decide whether to proceed, pivot
to an evasion technique, or abort on a host with unfamiliar security
tooling.

## Hypothesis
A normal user or routine business process has no reason to query
`root\SecurityCenter2` for `AntiVirusProduct` — this is an
administrator/IT-tooling query, not something that occurs incidentally
during normal work. An attacker who has already achieved code execution
and is deciding what to do next (drop a payload, escalate, move
laterally) has a strong incentive to check what's watching first, since
the answer changes their next move.

## Threat intelligence context
Sourced from a DFIR Report writeup on a BlackSuit ransomware
intrusion — assessed as part of the same lineage/attack-family this
repo's own IR-2026-004 incident belongs to (Chaos, BlackSuit's
documented successor). This specific check had never been run against
OMNIA's own telemetry as of the source incident's checklist; treat a
clean result with the same caution as any other never-validated query
in this repo until confirmed against real data.

## Query

**Sentinel / Defender XDR**
```kusto
let lookback = 1d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_all ("SecurityCenter2", "AntiVirusProduct")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
Same query works unchanged in Defender XDR advanced hunting and
Sentinel — `DeviceProcessEvents` is a shared MDE-sourced table in both.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Discovery — T1518.001 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `wmic.exe SecurityCenter2 ... AntiVirusProduct` invocation where
`InitiatingProcessFileName` is a shell spawned via an unusual chain
(e.g. `cmd.exe` under `explorer.exe` via a Win+R ClickFix pattern, or a
script host) rather than a known IT-management tool. Review what ran on
the same device immediately after — this is reconnaissance, so the
interesting evidence is what the attacker did *because of* the answer,
not the query itself.

## False positive notes
Legitimate IT asset-management, compliance-scanning, and RMM tooling
(SCCM, Intune scripts, some AV/EDR products checking for competing
products during their own install) routinely run this exact query.
Baseline which management tools in this environment do this
legitimately and exclude by `InitiatingProcessFileName` or a known
service-account `AccountName` rather than suppressing the command
pattern itself.

## Detection blind spots
`wmic.exe` is deprecated in current Windows builds and increasingly
blocked or absent by default — an attacker using the PowerShell
equivalent (`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName
AntiVirusProduct`) or a direct WMI/COM API call from a compiled binary
produces no signal here at all. This rule only catches the specific
`wmic.exe` command-line invocation.

## Validation
No confirmed Atomic Red Team test identified for this exact WMI query
pattern. Validate manually: run `WMIC /Node:localhost
/Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
/Format:List` on a lab device and confirm the rule fires.

## References
- MITRE ATT&CK: [T1518.001](https://attack.mitre.org/techniques/T1518/001/) (Security Software Discovery)
- Source: DFIR Report — BlackSuit ransomware case study
