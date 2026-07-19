---
id: interactive-privilege-escalation
title: Interactive Privilege Escalation
tactic: Privilege Escalation, Defense Evasion
technique: T1548.002
sub_technique_name: Abuse Elevation Control Mechanism - Bypass User Account Control
severity: medium
confidence: medium
status: production
platforms:
- defender_xdr
- sentinel
data_sources:
- DeviceProcessEvents
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
owner: calvin
last_reviewed: '2026-07-19'
analytics_rule:
  id: 3eac4f2f-5468-4e0d-a691-4c1912789064
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics:
  - PrivilegeEscalation
  - DefenseEvasion
  relevantTechniques:
  - T1548.002
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: Name
      columnName: User
  - entityType: Host
    fieldMappings:
    - identifier: Name
      columnName: DeviceName
---

# Interactive Privilege Escalation

## Summary
Flags a non-system interactive user session spawning a High-integrity or
fully-elevated process from a UAC-prompting binary (msiexec/cmd/
powershell/wscript/rundll32), excluding processes initiated by the
SYSTEM context. Targets manual UAC-consent elevation or social-
engineered elevation on an endpoint, not service-account or scheduled-
task elevation.

## Hypothesis
An interactive (desktop-session) user elevating a process to High
integrity through one of a small set of common admin tools is either
legitimate ad-hoc admin work or a social-engineered/manual elevation
worth reviewing — excluding SYSTEM/service-context elevation removes the
overwhelming majority of routine, non-interactive elevation so what's
left is weighted toward human-triggered events.

## Threat intelligence context
No named actor, malware family, or campaign — a generic interactive-
elevation detection.

## Query

**Defender XDR / Sentinel**
```kusto
DeviceProcessEvents
| where AccountName !in~ ("system","local service","network service")
| where isnotempty(AccountName)
| where ProcessIntegrityLevel == "High" or ProcessTokenElevation in ("Full", 2)
| where InitiatingProcessIntegrityLevel !in ("System")      // skip service/system context
| where InitiatingProcessFileName in~ ("explorer.exe","msiexec.exe","cmd.exe","powershell.exe","wscript.exe","rundll32.exe")
| where InitiatingProcessParentFileName !in~ ("svchost.exe","services.exe","taskeng.exe","taskhostw.exe")
| where CreatedProcessSessionId > 0 or InitiatingProcessSessionId > 0  // interactive desktop
| extend User = tostring(AccountName)
| project Timestamp, DeviceName, User, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          ProcessIntegrityLevel, ProcessTokenElevation, ReportId
| order by Timestamp desc
```
(Same query works unchanged in both — this uses only shared
`DeviceProcessEvents` schema fields.)

## What a hit looks like
A named user (not a service account) elevating a process to High
integrity via a common admin binary during an interactive session.
Review `ProcessCommandLine` for anything unexpected and confirm the user
intended to run an elevated task.

## False positive notes
Legitimate IT/helpdesk work, developers running elevated tooling, and
users installing approved software (msiexec-driven installs) will
appear here regularly on an environment where local admin rights or
Admin By Request-style elevation are in normal use. Cross-reference
against [`admin-by-request/`](../admin-by-request/) rules if that
product is deployed — an elevation here with no corresponding ABR
session may be more notable than one that has one.

## Detection blind spots
This rule does **not** catch the classic registry-hijack UAC-bypass
LOLBin chains (fodhelper.exe, eventvwr.exe, computerdefaults.exe,
sdclt.exe, SilentCleanup) — in each of those, the auto-elevating LOLBin
itself is the `InitiatingProcessFileName`, and none of them are in this
rule's allowlist (`explorer.exe`, `msiexec.exe`, `cmd.exe`,
`powershell.exe`, `wscript.exe`, `rundll32.exe`). Those techniques don't
trigger a UAC consent prompt at all, which is precisely why attackers
use them — and precisely why they fall outside what this rule, as
written, is actually checking for. This rule covers manual/social-
engineered interactive elevation, not silent UAC-bypass techniques.

## Validation
Atomic Red Team has extensive T1548.002 coverage (Atomic Tests #1-#17,
including Event Viewer, Fodhelper, ComputerDefaults, sdclt, and multiple
UACME methods), but — per the blind spot above — those specific tests
would **not** be expected to trigger this rule, since none of their
initiating binaries are in its allowlist. Running one of those tests
against a lab device and confirming this rule does *not* fire (while a
manual `Run as Administrator` on `cmd.exe`/`powershell.exe` from
`explorer.exe` *does*) would be a meaningful validation exercise —
proving the rule's actual scope matches its intended scope.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/endpoint/interactive_privilege_escalation.kql
- MITRE ATT&CK: [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Bypass User Account Control)
- Atomic Red Team T1548.002 (context on what this rule does *not* catch): https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md
