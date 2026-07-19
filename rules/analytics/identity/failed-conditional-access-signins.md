---
id: failed-conditional-access-signins
title: Failed Conditional Access Sign-ins on Risky Accounts
tactic: Initial Access
technique: T1078.004
sub_technique_name: Valid Accounts - Cloud Accounts
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
  id: fda9dcd1-5269-4154-993e-6d4d614ace85
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
  - InitialAccess
  relevantTechniques:
  - T1078.004
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserPrincipalName
---

# Failed Conditional Access Sign-ins on Risky Accounts

## Summary
Flags sign-ins blocked by Conditional Access (password-change-required,
strong-auth-required, or missing session info) where the account was
already flagged medium/high risk during sign-in. Surfaces credential-
compromise attempts that CA is currently absorbing — worth a proactive
password reset/session revoke rather than waiting for a successful
bypass.

## Hypothesis
A sign-in attempt that both trips a specific CA error condition and
carries a medium/high risk score is more informative together than
either signal alone — CA blocking it means the attacker hasn't gotten
in yet, but the risk score means the attempt itself looks like a real
compromise attempt worth acting on now, before CA's protection is
bypassed or lifted.

## Threat intelligence context
No named actor, malware family, or campaign — generic credential-
compromise-attempt detection.

## Query

**Sentinel**
```kusto
SigninLogs
| where ConditionalAccessStatus == "failure"
| where Status.errorCode == 50125 or Status.errorCode == 50074 or Status.errorCode == 50058
| where RiskLevelDuringSignIn in ("medium", "high")
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## What a hit looks like
A `UserPrincipalName` with a blocked sign-in and medium/high risk —
proactively reset the password and revoke sessions rather than waiting
to see if a later attempt succeeds.

## False positive notes
A legitimate user who's had a recent risky sign-in flagged (e.g., new
travel) and is now hitting a password-change-required or strong-auth
prompt as part of normal remediation will also match. Distinguish by
whether the user has already been through incident remediation for that
risk event.

## Detection blind spots
Only catches three specific error codes (50125, 50074, 50058) — a
Conditional Access block via a different mechanism (device compliance,
location, app restriction) produces no signal here even on a risky
account. If Entra ID Protection's risk scoring itself is what's evaded
(e.g., an attacker who looks unremarkable to the risk engine), this rule
never sees the attempt regardless of CA outcome.

## Validation
No confirmed Atomic Red Team test identified — T1621 (the closest
related technique) is listed in ART as awaiting a contributed test, and
this specific CA-error-code + risk-level combination isn't itself a
technique ART simulates directly. Validate manually: trigger a
password-change-required or strong-auth-required CA block on an account
Entra ID Protection has already flagged medium/high risk, and confirm
the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/failed_conditional_access_signins.kql
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
