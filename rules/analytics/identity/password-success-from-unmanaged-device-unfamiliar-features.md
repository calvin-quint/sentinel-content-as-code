---
id: password-success-from-unmanaged-device-unfamiliar-features
title: Successful Password Sign-in from Unmanaged Device with Unfamiliar Features
tactic: Initial Access
technique: T1078.004
sub_technique_name: Valid Accounts - Cloud Accounts
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
  id: 43bd0010-93a0-4afd-a61c-0a5dad31d238
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
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: IPAddress
---

# Successful Password Sign-in from Unmanaged Device with Unfamiliar Features

## Summary
Flags a correct-password sign-in that succeeds from a device with no
Entra device ID (unmanaged/BYOD) while Identity Protection flags
"unfamiliarFeatures" risk — an atypical browser/device/location
combination for that user. The combination of unmanaged endpoint plus
anomalous signal is a strong indicator of credential compromise rather
than routine BYOD use.

## Hypothesis
Unmanaged-device sign-ins alone are common (routine BYOD) and
`unfamiliarFeatures` alone is common (any new browser/device
combination). Together — an unregistered device *and* a signal Identity
Protection itself hasn't seen before for that user — the joint
probability of legitimate coincidence is much lower than either
condition individually.

## Threat intelligence context
No named actor, malware family, or campaign — generic credential-
compromise detection.

## Query

**Sentinel**
```kusto
SigninLogs
| extend AuthDetails = parse_json(AuthenticationDetails)
| mv-expand AuthDetails
| where tostring(AuthDetails.authenticationMethod) == "Password"
| where tostring(AuthDetails.authenticationStepResultDetail) == "Correct password"
| where tostring(AuthDetails.succeeded) == "true"
| extend DeviceId = tostring(DeviceDetail.deviceId)
| where isempty(DeviceId)
| where RiskEventTypes has "unfamiliarFeatures"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AutonomousSystemNumber,
    Location = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    AppDisplayName,
    ConditionalAccessStatus,
    ResultType,
    RiskLevelDuringSignIn,
    RiskEventTypes,
    ClientAppUsed
| order by TimeGenerated desc
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## What a hit looks like
A `UserPrincipalName` with no `DeviceId`, correct password, and
`unfamiliarFeatures` in `RiskEventTypes`. Check `ClientAppUsed` and
`Location`/`AutonomousSystemNumber` for anything inconsistent with the
user's normal pattern.

## False positive notes
A user's first sign-in from a brand-new personal device (new phone,
freshly reinstalled browser) that's never been enrolled will legitimately
produce this pattern once. It shouldn't recur for the same device/user
combination — repeated hits from what should be the same device are more
suspicious than a single one.

## Detection blind spots
Depends entirely on Identity Protection's own `unfamiliarFeatures`
classifier firing — an attacker whose sign-in doesn't trip that specific
risk type (e.g., because Identity Protection's model considers the
attributes familiar for unrelated reasons) evades this rule even from an
unmanaged device. Also only checks `DeviceId` emptiness as the
"unmanaged" signal — a device with a spoofed or reused device ID
wouldn't be flagged.

## Validation
No confirmed Atomic Red Team test identified — Entra ID Protection's
`unfamiliarFeatures` risk classification isn't a technique ART
simulates directly. Validate manually: sign in with a test account's
correct password from a browser/device profile the account has never
used, and confirm the rule fires (requires enough baseline history for
Identity Protection to consider it unfamiliar).

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/password_success_from_unmanaged_device_unfamiliar_features.kql
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
