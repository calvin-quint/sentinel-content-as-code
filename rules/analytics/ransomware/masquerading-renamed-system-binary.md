---
id: masquerading-renamed-system-binary
title: Masquerading - Renamed System Binary Execution
tactic: Defense Evasion
technique: T1036
sub_technique_name: Masquerading
severity: high
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
  atomic_test: T1036.003-4
  atomic_test_url: "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md#atomic-test-4-masquerading---wscriptexe-running-as-svchostexe"
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: 383706f3-ce8d-4d3b-88f1-a0b1e35cacf6
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
  relevantTechniques: [T1036]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: AccountName
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
last_reviewed: "2026-07-19"
---

# Masquerading - Renamed System Binary Execution

## Summary
Detects a process using a well-known Windows system binary filename
(`svchost.exe`, `lsass.exe`, `csrss.exe`, etc.) but launched from
outside its legitimate install directory, or whose embedded version-
info original filename doesn't match the on-disk filename — a common
technique to blend in with normal system activity and slip past naive
name-based allowlists.

## Hypothesis
Legitimate Windows system binaries only ever run from a small, fixed
set of directories (`System32`/`SysWOW64`, or `C:\Windows\` directly
for `explorer.exe`). A process using one of these exact filenames but
running from anywhere else — or whose internal PE version metadata
(`ProcessVersionInfoOriginalFileName`) doesn't match its on-disk name —
is inconsistent with the real system binary and consistent with an
attacker renaming a different tool to blend into process-list review.

## Threat intelligence context
No named actor, malware family, or campaign — a generic masquerading
detection used across a wide range of malware and manual intrusion
activity, including many ransomware precursor toolsets.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let systemBinaries = dynamic([
    "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "winlogon.exe", "wininit.exe",
    "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe"
]);
let legitimatePathFragments = dynamic([@"c:\windows\system32\", @"c:\windows\syswow64\"]);

DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (systemBinaries)
| extend FolderPathLower = tolower(FolderPath)
// explorer.exe legitimately runs from C:\Windows\ directly, not System32 - handle separately
| where (FileName =~ "explorer.exe" and FolderPathLower !~ @"c:\windows\explorer.exe")
   or (FileName !~ "explorer.exe" and not(FolderPathLower has_any (legitimatePathFragments)))
| extend NameVsInternalMismatch = iff(
    isnotempty(ProcessVersionInfoOriginalFileName) and tolower(ProcessVersionInfoOriginalFileName) != tolower(FileName),
    true, false)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          ProcessVersionInfoOriginalFileName, NameVsInternalMismatch, InitiatingProcessFileName, ReportId
| order by Timestamp desc
```
(Same query works unchanged in both — this uses only shared
`DeviceProcessEvents` schema fields.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Defense Evasion — T1036 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` · `File.Name = FileName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `FileName` matching a system binary but running from an unexpected
`FolderPath`, especially combined with `NameVsInternalMismatch = true`
(the PE's own embedded original-filename metadata disagrees with what
it's currently named). The mismatch flag alone, without a path anomaly,
is a weaker signal and worth a quick check but not automatic escalation.

## False positive notes
Rare cases of legitimate third-party software bundling a binary
literally named the same as a system process, or lab/test machines
intentionally running these binaries from copied directories, can
trigger this. Maintain an allowlist of known non-standard-but-approved
paths (e.g., WDAC/AppLocker staging folders) if noisy.

## Detection blind spots
Only checks a fixed list of well-known system binary names and two
legitimate path fragments — a masquerade using a filename not on the
list (or a legitimate path this org uses that isn't System32/SysWOW64,
e.g. a non-default Windows install drive) produces false negatives or
false positives respectively. An attacker who also forges the PE
version-info metadata to match the fake name defeats the
`NameVsInternalMismatch` check specifically, leaving only the path
anomaly as a signal.

## Validation
Related Atomic Red Team test identified (sub-technique T1036.003, not
the parent T1036 this rule is tagged with): [T1036.003 Atomic Test #4 — Masquerading: wscript.exe running as svchost.exe](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md#atomic-test-4-masquerading---wscriptexe-running-as-svchostexe).
Not yet executed against a lab device — running it and confirming both
the path-anomaly and version-info-mismatch signals fire is the next
step.

## References
- MITRE ATT&CK: [T1036](https://attack.mitre.org/techniques/T1036/) (Masquerading)
