---
id: sharepoint-or-m365-group-deleted
title: SharePoint Site or M365 Group Deleted
tactic: Impact
technique: T1485
sub_technique_name: Data Destruction
severity: medium
confidence: high
status: production
platforms:
- sentinel
data_sources:
- CloudAppEvents
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
owner: calvin
last_reviewed: '2026-07-19'
analytics_rule:
  id: 451d4d5b-e07f-4d78-9d2f-71623b5f3f9f
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
  - Impact
  relevantTechniques:
  - T1485
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: DeletedBy
---

# SharePoint Site or M365 Group Deleted

## Summary
Detects deletion of an M365 Group or a SharePoint site, merged from two
sources (Entra group-deletion audit + SharePoint site-delete activity).
Covers both a compromised/insider account destroying collaboration data
and accidental deletion needing fast recovery — the 30-day soft-delete
window for M365 Groups/SharePoint makes early detection matter for
restorability.

## Hypothesis
Group and site deletions are infrequent, high-impact, and almost always
deliberate administrative actions with a paper trail. Surfacing every
deletion event — regardless of whether it turns out to be malicious or
accidental — is worth the noise given how narrow the recovery window is;
this rule doesn't try to score intent, only to guarantee visibility fast
enough to act within the soft-delete window.

## Threat intelligence context
No named actor, malware family, or campaign — a data-destruction/
availability detection applicable to both malicious and accidental
deletion.

## Query

**Sentinel**
```kusto
union
(
    CloudAppEvents
    | where ActionType has "Delete group" or ActionType has "DeleteGroup"
    | extend Parsed = parse_json(RawEventData)
    | mv-expand ModifiedProp = Parsed.ModifiedProperties
    | where ModifiedProp.Name == "GroupType"
    | extend
        GroupType = tostring(ModifiedProp.OldValue),
        Time = todatetime(Parsed.CreationTime),
        DeletedBy = tostring(Parsed.UserId),
        Target = tostring(Parsed.ObjectId)
    | where GroupType contains "M365 group"
),
(
    OfficeActivity
    | where OfficeWorkload == "SharePoint"
    | where Operation == "SiteDeleted"
    | extend
        Time = TimeGenerated,
        DeletedBy = tostring(UserId),
        Target = tostring(Site_Url)  // Use Site_Url for SharePoint site URL
)
```
(No Defender XDR variant — `CloudAppEvents` and `OfficeActivity` are
Sentinel/M365 audit tables with no single Defender XDR portal
equivalent for this union.)

## What a hit looks like
A `DeletedBy` account and `Target` (group ObjectId or SharePoint
Site_Url) with a `Time`. Confirm with the account owner or IT whether
the deletion was planned; if not, begin restoration immediately given
the 30-day soft-delete window.

## False positive notes
Legitimate offboarding/cleanup processes delete groups and sites
routinely. This rule intentionally doesn't try to separate "planned" from
"unplanned" deletion — that judgment call belongs to the analyst
reviewing `DeletedBy` against change records, not the query.

## Detection blind spots
Only covers M365 Groups and SharePoint sites specifically — deletion of
other collaboration surfaces (Teams-only channels without an underlying
group, OneDrive personal sites) isn't covered by either source here. The
`GroupType contains "M365 group"` filter also means non-M365 group types
(security groups, distribution lists) are excluded by design, so a
malicious actor deleting those instead produces no signal from this
rule.

## Validation
No confirmed Atomic Red Team test identified — M365 Group/SharePoint
deletion is a SaaS-administrative action outside ART's typical
host/cloud-infrastructure coverage. Validate manually: delete a test
M365 Group and a test SharePoint site in a lab tenant and confirm both
paths of the union produce a result.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/governance/sharepoint_or_m365_group_deleted.kql
- MITRE ATT&CK: [T1485](https://attack.mitre.org/techniques/T1485/) (Data Destruction)
