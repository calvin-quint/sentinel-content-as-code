---
id: internal-mail-forwarding
title: Mail Forwarding Rule Classification (Internal vs. External)
tactic: Collection
technique: T1114.003
sub_technique_name: Email Forwarding Rule
severity: low
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- CloudAppEvents
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
  id: 661613d6-98cb-4adb-a5fd-cb06c653b8c6
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
  - T1114.003
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserIdClean
---

# Mail Forwarding Rule Classification (Internal vs. External)

## Summary
Baseline/triage query. Extracts every inbox rule with a "Forward" action
from the raw Exchange audit event and labels each by whether the
recipient's domain matches the sender's own domain. Use the "Forward to
External" rows as the actionable subset and "Forward to Internal" rows
as expected noise.

## Hypothesis
Not itself a threat detection — this is a classification/triage feed.
Its underlying assumption is that separating internal-forward noise from
external-forward signal at query time (rather than manually per row) is
what makes forward-rule review tractable at volume.

## Threat intelligence context
No named actor, malware family, or campaign — a triage-classification
query, not threat-intel-driven.

## Query

**Sentinel**
```kusto
CloudAppEvents
| where Application contains "Exchange"
| where ActionType contains "InboxRules"
| extend OpsProps = parse_json(RawEventData).OperationProperties
| mv-expand prop = OpsProps
| where prop.Name == "RuleActions"
| extend RuleActionsArray = parse_json(tostring(prop.Value))
| mv-expand actionItem = RuleActionsArray
| where tostring(actionItem.ActionType) == "Forward"
| extend RecipientsArray = todynamic(actionItem.Recipients)
| mv-expand Recipient = RecipientsArray
| extend RecipientClean = tolower(tostring(Recipient))
| extend UserIdClean = tolower(tostring(parse_json(RawEventData).UserId))
| extend UserDomain = tostring(split(UserIdClean, "@")[1])
| extend RecipientDomain = tostring(split(RecipientClean, "@")[1])
| extend Result = iff(RecipientDomain != UserDomain, "Forward to External", "Forward to Internal")
| project TimeGenerated, UserIdClean, RecipientClean, RecipientDomain, Result
| sort by TimeGenerated desc
```
(No Defender XDR variant — `CloudAppEvents` is a Sentinel/Defender for
Cloud Apps table.)

## What a hit looks like
Filter to `Result == "Forward to External"` for the actionable subset;
"Forward to Internal" rows are expected and lower priority.

## False positive notes
This query's whole purpose is separating expected noise ("Forward to
Internal") from the subset worth reviewing — treat internal-forward
matches as informational only.

## Detection blind spots
Only classifies by exact domain match — a forward to an external
partner organization the org has a legitimate relationship with still
lands in "Forward to External" alongside genuinely suspicious forwards,
so this doesn't replace the need for human judgment on each external
row. Overlaps conceptually with
[`external_mail_forwarding.md`](external_mail_forwarding.md), which uses
a different data source (`OfficeActivity` vs `CloudAppEvents`) and
covers mailbox-level forwarding in addition to inbox rules.

## Validation
Not applicable in the usual sense — this is a classification/triage
query, not a specific attack behavior to simulate. Its logic can be
validated by creating both an internal and an external forward rule in a
lab tenant and confirming each is labeled correctly.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/internal_mail_forwarding.kql
- MITRE ATT&CK: [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Forwarding Rule)
