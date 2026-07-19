---
id: successful-authentication-with-high-risk-ca-block
title: Successful Authentication Steps on a High-Risk, CA-Blocked Sign-in
tactic: Initial Access
technique: T1078.004
sub_technique_name: Valid Accounts - Cloud Accounts
severity: high
confidence: high
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
  id: 80c7cd14-7b7e-4534-bb22-2469aade3dbd
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

# Successful Authentication Steps on a High-Risk, CA-Blocked Sign-in

## Summary
Flags sign-ins where Conditional Access blocked the overall attempt
(`ResultType` 53003, high risk) but the underlying authentication
step(s) — password/MFA — actually succeeded. This means the credentials/
second factor were valid; CA is the only thing that stopped the sign-in,
so these accounts warrant a credential reset even though no breach
technically occurred.

## Hypothesis
A sign-in blocked purely by policy, where every individual auth step
underneath the block actually succeeded, tells you the attacker (or
account) had everything needed to get in — CA is a control, not proof the
credentials are safe. Verifying the block "actually blocked something"
(valid steps, not just a failed password attempt CA also happened to
reject) is what separates a real near-miss from routine noise.

## Threat intelligence context
No named actor, malware family, or campaign — generic detection for
confirming CA is the only barrier standing between an attacker and
access.

## Query

**Sentinel**
```kusto
SigninLogs
| where ResultType == 53003
| where ResultDescription has "Access has been blocked due to conditional access policies."
| where RiskLevelDuringSignIn == "high"
| extend AuthDetails = parse_json(AuthenticationDetails)
| mv-expand AuthDetails
| where tostring(AuthDetails.succeeded) == "true"
| project
    TimeGenerated,
    UserDisplayName,
    UserPrincipalName,
    IPAddress,
    Location = tostring(LocationDetails.countryOrRegion),
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    AuthenticationMethod = tostring(AuthDetails.authenticationMethod),
    AuthSucceeded = tostring(AuthDetails.succeeded),
    ConditionalAccessPolicies,
    UserAgent,
    ResourceDisplayName,
    Status
| order by TimeGenerated desc
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## What a hit looks like
A `UserPrincipalName` with `ResultType == 53003` where the underlying
`AuthenticationMethod` step shows `succeeded == true` — this means valid
credentials (and MFA, if required) were presented. Reset credentials and
review `ConditionalAccessPolicies` to confirm which policy actually
stopped it.

## False positive notes
None expected in the usual sense — if the auth steps genuinely
succeeded and CA blocked on high risk, that's exactly the scenario this
rule is meant to surface. The main judgment call is how quickly to act,
not whether the hit is "real."

## Detection blind spots
Only catches the specific `ResultType == 53003` block reason — a CA
block via a different result code produces no signal even if the
underlying auth steps succeeded and risk was high. Also depends on
`RiskLevelDuringSignIn == "high"` exactly — a medium-risk block with
fully successful auth steps (arguably still worth investigating) isn't
covered.

## Validation
No confirmed Atomic Red Team test identified — this is a Conditional
Access-policy-interaction pattern, not a technique ART simulates
directly. Validate manually: trigger a high-risk sign-in that
successfully completes password + MFA but gets blocked by a CA policy in
a lab tenant, and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/successful_authentication_with_high_risk_ca_block.kql
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
