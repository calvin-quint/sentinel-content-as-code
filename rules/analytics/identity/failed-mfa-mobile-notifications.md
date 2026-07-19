---
id: failed-mfa-mobile-notifications
title: Failed MFA Mobile Push Notification (Correct Password, Non-US)
tactic: Credential Access
technique: T1621
sub_technique_name: Multi-Factor Authentication Request Generation
severity: high
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
  id: 4029bb8d-632a-4ffb-8654-1bd5b27b9afa
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
  relevantTechniques:
  - T1621
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserPrincipalName
---

# Failed MFA Mobile Push Notification (Correct Password, Non-US)

## Summary
Flags the password step succeeding but the mobile app push notification
being denied/failing, from a non-US location — the signature of an
attacker with a valid stolen password triggering MFA push fatigue/
bombing while the real user declines the prompt.

## Hypothesis
A correct password paired with a denied push notification from outside
the US is much more consistent with an attacker who has the password but
not the device than with a legitimate user mistyping a PIN or fat-
fingering a prompt — the geography constraint specifically targets the
case where the real user (presumably in-region) is declining a push
they didn't expect.

## Threat intelligence context
No named actor, malware family, or campaign — targets the general MFA-
fatigue/push-bombing attack pattern.

## Query

**Sentinel**
```kusto
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where Status !contains "requirement satisfied"
| where AuthenticationDetails contains "Correct password"
| where AuthenticationDetails contains '"Mobile app notification","succeeded":false'
| where Status !contains "success"
| where Location != "US"
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## What a hit looks like
A `UserPrincipalName` with a correct-password step and a denied mobile
push from a non-US location. Repeated instances for the same user in a
short window is the clearest push-bombing signature — correlate with
[`failed_passwordless_mfa.md`](failed_passwordless_mfa.md) and
[`mfa_failure_outside_us.md`](mfa_failure_outside_us.md) for the broader
picture.

## False positive notes
A legitimate user traveling internationally who mis-taps or ignores a
push notification will match. The `Location != "US"` filter is a
US-centric assumption — for a genuinely global workforce, this narrows
coverage to only non-US-originating attempts and will miss the
equivalent pattern originating from within the US.

## Detection blind spots
Only catches the specific "Mobile app notification" method string — an
attacker triggering SMS or voice-call MFA methods instead produces no
signal here. The hardcoded `Location != "US"` filter means an attacker
operating from US-based infrastructure (a US VPS/proxy) evades this rule
entirely regardless of how many pushes they trigger.

## Validation
No confirmed Atomic Red Team test identified — T1621 is currently listed
in ART as awaiting a contributed test case. Validate manually: with a
test account's correct password, trigger repeated mobile push prompts
from a non-US IP and decline them, then confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/failed_mfa_mobile_notifications.kql
- MITRE ATT&CK: [T1621](https://attack.mitre.org/techniques/T1621/) (Multi-Factor Authentication Request Generation)
