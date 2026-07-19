---
id: mfa-failure-outside-us
title: MFA Failure Outside the US (Correct Password)
tactic: Credential Access, Initial Access
technique: T1621, T1078
sub_technique_name: Multi-Factor Authentication Request Generation / Valid Accounts
severity: medium
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- SigninLogs
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
  id: d3116762-c4ee-444f-83f2-b74af4dbd01f
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
  - CredentialAccess
  - InitialAccess
  relevantTechniques:
  - T1621
  - T1078
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserPrincipalName
---

# MFA Failure Outside the US (Correct Password)

## Summary
Broader companion to
[`failed_mfa_mobile_notifications.md`](failed_mfa_mobile_notifications.md) —
flags any failed MFA step following a correct password, sourced from
outside the US, across all MFA method types rather than mobile push
specifically. Catches attackers who've obtained valid passwords but
can't clear the second factor from unfamiliar geography.

## Hypothesis
A correct password combined with any failed MFA step from outside the US
is a broader net than the mobile-push-specific rule: it assumes the same
underlying logic (valid credentials, failed second factor, unexpected
geography) generalizes across MFA method types, not just push
notifications.

## Threat intelligence context
No named actor, malware family, or campaign — generalizes the mobile-
push-specific detection to all MFA methods.

## Query

**Sentinel**
```kusto
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where Location != "US"
| where tostring(Status) !contains "success"
| where tostring(AuthenticationDetails) contains "Correct password"
| extend AuthDetails = parse_json(AuthenticationDetails)
| mv-expand AuthDetails
| extend
    StepResult = tostring(AuthDetails.authenticationStepResultDetail),
    StepSucceeded = tostring(AuthDetails.succeeded)
| where StepSucceeded == "false"
| where StepResult !has "requirement satisfied"
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## What a hit looks like
A `UserPrincipalName` with a correct-password step and a failed MFA step
of any type, from outside the US. Compare against
`failed_mfa_mobile_notifications.md` results for the same user — overlap
strengthens confidence.

## False positive notes
Same caveat as the mobile-push-specific sibling rule: legitimate
international travel can produce this pattern. The US-centric
`Location != "US"` filter also means this only makes sense for an
org whose workforce is primarily US-based.

## Detection blind spots
The hardcoded `Location != "US"` filter means an attacker operating from
US-based infrastructure evades this rule entirely. It also depends on
`AuthenticationDetails` containing the literal string "Correct
password" — any variation in how Entra ID reports that step (e.g., a
different authentication method producing a differently worded result)
would not match.

## Validation
No confirmed Atomic Red Team test identified — T1621 is listed in ART as
awaiting a contributed test case. Validate manually: with a test
account's correct password, fail an MFA step from a non-US IP and
confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/mfa_failure_outside_us.kql
- MITRE ATT&CK: [T1621](https://attack.mitre.org/techniques/T1621/) (Multi-Factor Authentication Request Generation), [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts)
