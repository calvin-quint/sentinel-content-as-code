---
id: multiple-failed-signins-then-success
title: Multiple Failed Sign-ins Followed by a Success (Possible Password Spray)
tactic: Credential Access
technique: T1110, T1110.003
sub_technique_name: Brute Force / Password Spraying
severity: high
confidence: medium
status: production
platforms: [sentinel]
data_sources: [SigninLogs]
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references: []
validated:
  atomic_test: T1110.003-7
  atomic_test_url: "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md#atomic-test-7-password-spray-microsoft-online-accounts-with-msolspray-azureo365"
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: 3d4e5f6a-7b8c-4d9e-a0b1-c2d3e4f5a6b7
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  requiredDataConnectors:
    - connectorId: AzureActiveDirectory
      dataTypes: [SigninLogs]
  tactics: [CredentialAccess]
  relevantTechniques: [T1110, T1110.003]
  entityMappings:
    - entityType: Account
      fieldMappings:
        - identifier: FullName
          columnName: UserPrincipalName
    - entityType: IP
      fieldMappings:
        - identifier: Address
          columnName: SuccessIP
  incidentConfiguration:
    createIncident: true
    groupingConfiguration:
      enabled: true
      reopenClosedIncident: false
      lookbackDuration: PT5H
      matchingMethod: AllEntities
  eventGroupingSettings:
    aggregationKind: SingleAlert
owner: calvin
last_reviewed: "2026-07-19"
---

# Multiple Failed Sign-ins Followed by a Success (Possible Password Spray)

## Summary
Detects a user account with five or more failed Azure AD sign-ins
followed by a successful sign-in within a one hour window — a common
pattern for brute-force or password-spray attacks that succeed.

## Hypothesis
Five-plus failed sign-in attempts for one account followed by a success
in the same hour is a materially different pattern than a user
mistyping a password once or twice before getting it right — the
volume threshold specifically targets sustained guessing rather than
normal human error, on the assumption that a legitimate user rarely
fails five times in a row before succeeding.

## Threat intelligence context
No named actor, malware family, or campaign — a generic brute-force/
spray detection applicable to any credential-guessing attempt.

## Query

**Sentinel**
```kusto
let failed = SigninLogs
| where ResultType != 0
| summarize FailedCount = count(), FailedIPs = make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h);
let success = SigninLogs
| where ResultType == 0
| project SuccessTime = TimeGenerated, UserPrincipalName, SuccessIP = IPAddress, bin(TimeGenerated, 1h);
failed
| where FailedCount >= 5
| join kind=inner success on UserPrincipalName, TimeGenerated
| project TimeGenerated, UserPrincipalName, FailedCount, FailedIPs, SuccessTime, SuccessIP
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `PT1H` |
| Trigger | `gt 0` |
| Tactics / Techniques | Credential Access — T1110, T1110.003 |
| Entity mappings | `Account.FullName = UserPrincipalName` · `IP.Address = SuccessIP` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `UserPrincipalName` with `FailedCount >= 5` and a subsequent
`SuccessTime`. Compare `FailedIPs` against `SuccessIP` — a spray attack
succeeding from a different IP than the failed attempts (attacker
finally guessing right, or pivoting to a working credential from a
list) is higher-confidence than a single consistent IP throughout
(more consistent with a user's own repeated typos).

## False positive notes
A user who forgets a recently changed password and retries several
times before succeeding (or unlocking via a password manager
autofill mismatch) can trigger this legitimately. Cross-reference
`FailedIPs`/`SuccessIP` consistency and check whether the account had a
recent password change or MFA re-registration event around the same
time.

## Detection blind spots
The 1-hour bucket (`bin(TimeGenerated, 1h)`) means a slower spray spread
across multiple hours — 4 failures in one hour, then a success in the
next — evades the `FailedCount >= 5` threshold entirely, since each
hour's bucket is evaluated independently. A spray tool that only
attempts 1-4 passwords per account before moving on (low-and-slow
spraying across a large user list) also produces no signal here.

## Validation
Matching Atomic Red Team test identified: [T1110.003 Atomic Test #7 — Password Spray Microsoft Online Accounts with MSOLSpray (Azure/O365)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md#atomic-test-7-password-spray-microsoft-online-accounts-with-msolspray-azureo365).
Not yet executed against a lab tenant — running it and confirming both
the failed-attempt volume and an eventual success trigger the rule is
the next step.

## References
- MITRE ATT&CK: [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force), [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Password Spraying)
