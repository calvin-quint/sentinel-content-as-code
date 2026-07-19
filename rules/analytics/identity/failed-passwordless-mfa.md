---
id: failed-passwordless-mfa
title: Failed Passwordless/Phishing-Resistant MFA Step
tactic: Credential Access
technique: T1621, T1110
sub_technique_name: Multi-Factor Authentication Request Generation / Brute Force
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
  id: e1405ded-1520-42b9-8c86-2def9337845a
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
  - T1110
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserPrincipalName
---

# Failed Passwordless/Phishing-Resistant MFA Step

## Summary
Flags a failed authentication step against a phishing-resistant method
(FIDO2, Windows Hello, Passkey, Temporary Access Pass, Phone App
Notification). Legitimate users rarely fail these repeatedly — failures
usually mean an attacker with a stolen password hitting a hardware/
biometric barrier they can't satisfy, or a misconfigured registration
worth a support follow-up.

## Hypothesis
Phishing-resistant methods bind authentication to a physical device or
biometric that an attacker without possession of the device cannot
satisfy, regardless of what credentials they've stolen. Repeated
failures against these specific methods are a stronger signal than
failures against knowledge-based methods (passwords, OTP), since there's
a much narrower set of legitimate reasons for them to fail.

## Threat intelligence context
No named actor, malware family, or campaign — a generic detection for
attackers hitting a phishing-resistant-MFA wall.

## Query

**Sentinel**
```kusto
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| extend AuthDetails = parse_json(AuthenticationDetails)
| mv-expand AuthDetails
| extend
    StepMethod = tostring(AuthDetails.authenticationMethod),
    StepResult = tostring(AuthDetails.authenticationStepResultDetail),
    StepSucceeded = tostring(AuthDetails.succeeded)
| where StepSucceeded == "false"
| where StepMethod has_any (
    "FIDO2",
    "Windows Hello",
    "Temporary Access Pass",
    "Passwordless Phone",
    "Phone App Notification",
    "Passkey"
)
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## What a hit looks like
Repeated failures against one of the listed methods for the same
`UserPrincipalName` in a short window. A single isolated failure is
lower priority than a cluster.

## False positive notes
A user with a new or recently re-registered FIDO2 key/passkey, or a
Windows Hello enrollment that's misconfigured after a device rebuild,
can generate legitimate repeated failures. Check whether the user has an
open support ticket for device/authenticator issues before escalating.

## Detection blind spots
Only matches the specific method-name strings listed — a new or
differently-named phishing-resistant method Microsoft introduces later
wouldn't be caught until added. Also only sees failures, not successes,
so it can't distinguish "attacker repeatedly failing" from "legitimate
user finally succeeding after a few failed taps" without additional
context from a wider query.

## Validation
No confirmed Atomic Red Team test identified — T1621 is listed in ART as
awaiting a contributed test case, and phishing-resistant MFA failure
specifically isn't modeled as a distinct atomic. Validate manually:
attempt sign-in with an invalid/mismatched FIDO2 key or passkey against
a test account and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/failed_passwordless_mfa.kql
- MITRE ATT&CK: [T1621](https://attack.mitre.org/techniques/T1621/) (Multi-Factor Authentication Request Generation), [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force)
