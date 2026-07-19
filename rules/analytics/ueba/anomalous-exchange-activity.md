---
id: anomalous-exchange-activity
title: UEBA Anomalous Exchange Activity
tactic: Collection
technique: T1114.003
sub_technique_name: Email Collection - Email Forwarding Rule
severity: medium
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- Anomalies
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
  id: 60be7602-2865-4a9b-8639-51254ac5c487
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
    - identifier: FullName
      columnName: UserPrincipalName
    - identifier: Name
      columnName: Account_0_Name
    - identifier: UPNSuffix
      columnName: Account_0_UPNSuffix
owner: calvin
last_reviewed: '2026-07-19'
---

# UEBA Anomalous Exchange Activity

## Summary
Surfaces UEBA's "Anomalous user activities in Office Exchange" template,
split into two sub-signals: inbox-rule anomalies (post-compromise
persistence) and mail-access anomalies (collection). Inbox-rule
anomalies are flagged as the higher-fidelity signal and sorted first.

## Hypothesis
UEBA's Exchange anomaly template bundles two meaningfully different
behaviors — a new/modified inbox rule versus unusual mail-access volume
— that carry different confidence levels. An inbox-rule change is a
concrete persistence action with few legitimate reasons to be anomalous;
unusual mail access alone is a weaker, noisier signal. Splitting them
out and ranking inbox-rule anomalies first gets an analyst to the
higher-confidence cases without waiting on raw score alone.

## Threat intelligence context
No named actor, malware family, or campaign — this is a statistical/
UEBA-driven detection, not threat-intel-driven.

## Query

**Sentinel**
```kusto
Anomalies
| where TimeGenerated > ago(1h)
| where AnomalyTemplateName == "Anomalous user activities in Office Exchange"
| where Score >= 0.5
| extend ReasonsStr = tostring(AnomalyReasons)
| extend
    IsInboxRuleAnomaly = ReasonsStr has_any (
        "UpdateInboxRules",
        "NewInboxRule",
        "SetInboxRule"
    ),
    IsMailAccessAnomaly = ReasonsStr has_any (
        "MailItemsAccessed",
        "MessageBind"
    )
| summarize
    EventCount          = count(),
    MaxScore            = max(Score),
    FirstSeen           = min(TimeGenerated),
    LastSeen            = max(TimeGenerated),
    Descriptions        = make_set(Description, 5),
    AnomalyReasons      = make_set(ReasonsStr, 5),
    IsInboxRuleAnomaly  = max(tolong(IsInboxRuleAnomaly)),
    IsMailAccessAnomaly = max(tolong(IsMailAccessAnomaly))
    by UserPrincipalName, AnomalyTemplateName,
       Tactics, Techniques
| where isnotempty(UserPrincipalName)
| extend
    HighFidelitySignal  = IsInboxRuleAnomaly == 1,
    Account_0_Name      = tostring(split(UserPrincipalName, "@")[0]),
    Account_0_UPNSuffix = tostring(split(UserPrincipalName, "@")[1])
| project
    FirstSeen, LastSeen, UserPrincipalName,
    AnomalyTemplateName, MaxScore, EventCount,
    IsInboxRuleAnomaly, IsMailAccessAnomaly, HighFidelitySignal,
    Descriptions, AnomalyReasons, Tactics, Techniques,
    Account_0_Name, Account_0_UPNSuffix
| sort by HighFidelitySignal desc, MaxScore desc
```
(No Defender XDR variant — `Anomalies` is a Sentinel UEBA table with no
Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `PT1H` |
| Suppression | `PT24H` |
| Grouping | By account, 24h window |
| Entity mappings | `Account.FullName = UserPrincipalName` · `Account.Name = Account_0_Name` · `Account.UPNSuffix = Account_0_UPNSuffix` |
| Custom details | `MaxScore`, `IsInboxRuleAnomaly`, `IsMailAccessAnomaly`, `HighFidelitySignal`, `Descriptions`, `AnomalyReasons` |

## What a hit looks like
`HighFidelitySignal = true` (an inbox-rule anomaly) is the priority
tier — triage those first. `IsMailAccessAnomaly`-only hits are worth
review but lower urgency; check `MaxScore` and `Descriptions` for
context in either case.

## False positive notes
Mail-access anomalies alone can reflect legitimate behavior changes
(new role, new delegated mailbox access, a user catching up on email
after time off) rather than compromise. Inbox-rule anomalies are rarer
in legitimate use but not impossible — bulk mailbox migrations or
IT-initiated rule changes can trigger them; check `Descriptions` for
context before escalating.

## Detection blind spots
Entirely dependent on UEBA's own anomaly model surfacing the
"Anomalous user activities in Office Exchange" template in the first
place — this rule adds no independent detection logic, only splits and
ranks what UEBA already flagged. Like the sibling
[`high_score_anomalous_authentication.md`](high_score_anomalous_authentication.md)
rule, it inherits every blind spot of the underlying UEBA baseline model
(new/low-activity accounts have unreliable scoring).

## Validation
Not yet tested against a simulated attack. Validation to date is
inherited from UEBA's own model tuning, not a specific attack-simulation
run. Next step: create an inbox rule and generate unusual mail-access
volume in a lab tenant with enough baseline history, and confirm the
rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/ueba/anomalous_exchange_activity.kql
- MITRE ATT&CK: [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Forwarding Rule)
