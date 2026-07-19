---
id: inbox-rule-changes-by-user-lookup
title: Inbox Rule Changes by User
tactic: Collection
technique: T1114.003
sub_technique_name: Email Forwarding Rule
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
owner: calvin
last_reviewed: '2026-07-19'
analytics_rule: null
---

# Inbox Rule Changes by User

## Summary
Parameterized lookup, not a standalone detection. Given a `$UPN`, pulls
every inbox-rule create/modify event for that user. Used to build a full
rule-change timeline during an account-compromise investigation.

## Hypothesis
Not applicable — this is an investigative lookup rather than a
suspicious-behavior detection. It exists to answer "what rule changes
has this specific already-flagged account made" once an investigation
is already underway.

## Threat intelligence context
No fixed named threat — used generically once an account is already
under investigation for any reason.

## Query

**Sentinel**
```kusto
OfficeActivity
| where Operation contains "Inbox"
| where UserId contains "$UPN"
| extend RuleParameters = parse_json(Parameters)
| extend
    RuleName        = tostring(RuleParameters[0].Value),
    ForwardTo       = tostring(RuleParameters[1].Value),
    DeleteMessage   = tostring(RuleParameters[2].Value),
    MoveToFolder    = tostring(RuleParameters[3].Value)
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    RuleName,
    ForwardTo,
    DeleteMessage,
    MoveToFolder,
    Parameters,
    OfficeObjectId,
    OrganizationName
| order by TimeGenerated desc
```
Substitute the actual UPN under investigation for `$UPN`.

(No Defender XDR variant — `OfficeActivity` is a Sentinel/M365 audit
table with no Defender XDR portal equivalent.)

## What a hit looks like
A full timeline of every inbox-rule change for the user — review
`RuleName`, `ForwardTo`, `DeleteMessage`, and `MoveToFolder` for
persistence/exfiltration patterns (forwarding, silent deletion, archive-
all rules).

## False positive notes
Not applicable — targeted lookup against an already-identified account,
not a broad detection subject to noise.

## Detection blind spots
Relies on `RuleParameters` array indices (`[0]`, `[1]`, `[2]`, `[3]`)
mapping consistently to `RuleName`/`ForwardTo`/`DeleteMessage`/
`MoveToFolder` — if Exchange's audit log ever orders parameters
differently for a given rule type, these fields could be mislabeled.
Cross-check `Parameters` (the raw field) if the parsed columns look
inconsistent.

## Validation
Not applicable — this is a lookup template, not an auto-firing detection
with a behavior to simulate.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/inbox_rule_changes_by_user_lookup.kql
- MITRE ATT&CK: [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Forwarding Rule)
