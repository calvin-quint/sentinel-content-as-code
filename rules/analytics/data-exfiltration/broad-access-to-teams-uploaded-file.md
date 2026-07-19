---
id: broad-access-to-teams-uploaded-file
title: Broad Access to Teams Uploaded File
tactic: Collection
technique: T1213
sub_technique_name: Data from Information Repositories
severity: low
confidence: high
status: production
platforms:
- sentinel
data_sources:
- OfficeActivity
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
  id: 9ebe5de0-3ad5-4799-b4c8-9b6596756754
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
  - Collection
  relevantTechniques:
  - T1213
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: Name
      columnName: Account_0_Name
    - identifier: UPNSuffix
      columnName: Account_0_UPNSuffix
owner: calvin
last_reviewed: '2026-07-19'
---

# Broad Access to Teams Uploaded File

## Summary
Flags Teams-uploaded files accessed by 8+ distinct people within the
1-hour evaluation window. Replaces the built-in "Files uploaded to
teams and access summarized" gallery rule.

## Hypothesis
A file uploaded into a Teams chat and then downloaded/accessed by a
large number of distinct people in a short window is unusual for typical
1:1 or small-group chat file sharing — it's more consistent with a file
being deliberately widely distributed (potentially sensitive content
shared too broadly) than routine collaboration. The `>= 8` threshold was
picked empirically, not arbitrarily (see False positive notes).

## Threat intelligence context
No named actor, malware family, or campaign — a broad-sharing/oversight
detection, not threat-intel-driven.

## Query

**Sentinel**
```kusto
OfficeActivity
| where TimeGenerated > ago(1h)
| where RecordType =~ "SharePointFileOperation"
| where Operation =~ "FileUploaded"
| where UserId != "app@sharepoint"
| where SourceRelativeUrl has "Microsoft Teams Chat Files"
| join kind=leftouter (
    OfficeActivity
    | where TimeGenerated > ago(1h)
    | where RecordType =~ "SharePointFileOperation"
    | where Operation in ("FileDownloaded", "FileAccessed")
    | where UserId != "app@sharepoint"
    | where SourceRelativeUrl has "Microsoft Teams Chat Files"
) on OfficeObjectId
| extend userBag = bag_pack(UserId1, ClientIP1)
| summarize
    Accessors        = make_set(UserId1, 10000),
    AccessorBag      = make_bag(userBag, 10000)
    by TimeGenerated, UserId, OfficeObjectId, SourceFileName
| extend NumberUsersAccessed = array_length(bag_keys(AccessorBag))
| where NumberUsersAccessed >= 8
| extend
    AccountName      = tostring(split(UserId, "@")[0]),
    AccountUPNSuffix = tostring(split(UserId, "@")[1])
| project
    TimeGenerated,
    Uploader            = UserId,
    FileName            = SourceFileName,
    FileLocation        = OfficeObjectId,
    NumberUsersAccessed,
    AccessedBy          = AccessorBag,
    AccessorList        = Accessors,
    Account_0_Name      = AccountName,
    Account_0_UPNSuffix = AccountUPNSuffix
| sort by NumberUsersAccessed desc
```
(No Defender XDR variant — `OfficeActivity` is a Sentinel/M365 audit
table with no Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `PT1H` |
| Suppression | `PT24H` |
| Grouping | By account, 24h window |
| Entity mappings | `Account.Name = Account_0_Name` · `Account.UPNSuffix = Account_0_UPNSuffix` |
| Custom details | `NumberUsersAccessed`, `AccessedBy`, `FileName` |
| Replaces | Files uploaded to teams and access summarized (gallery) |

## What a hit looks like
A file with `NumberUsersAccessed >= 8`, sorted descending — review
`FileName` and `AccessorList` for sensitivity and whether that many
people should reasonably have accessed it.

## False positive notes
Threshold was empirically tuned against 90 days of live tenant data:
`>= 8` reduced 3,121 candidate rows to 58 (~0.6/day). Legitimate large-
team announcements or company-wide shared documents in big Teams
channels will still occasionally cross this threshold — check the
channel/chat context before treating every hit as a leak.

## Detection blind spots
Only covers files uploaded specifically into "Microsoft Teams Chat
Files" — a file shared via a direct SharePoint/OneDrive link outside a
Teams chat context isn't covered by this rule. The 1-hour window also
means broad access that accumulates gradually over a longer period (a
file downloaded by 8+ people spread across several days) won't trigger,
since each hourly evaluation only sees that hour's accessors.

## Validation
No confirmed Atomic Red Team test identified — this is an M365/SharePoint-
specific access-pattern detection, not a technique ART simulates.
Validate manually: upload a test file into a Teams chat and have 8+ test
accounts access it within an hour in a lab tenant, then confirm the rule
fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/broad_access_to_teams_uploaded_file.kql
- Replaces built-in Sentinel gallery rule: "Files uploaded to teams and access summarized"
- MITRE ATT&CK: [T1213](https://attack.mitre.org/techniques/T1213/) (Data from Information Repositories)
