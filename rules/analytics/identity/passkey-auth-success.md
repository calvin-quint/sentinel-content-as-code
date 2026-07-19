---
id: passkey-auth-success
title: Successful Passkey Authentication
tactic: null
technique: null
sub_technique_name: null
severity: low
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
  id: 22541135-9e00-40d7-95cc-c016d4830ff6
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserPrincipalName
---

# Successful Passkey Authentication

## Summary
Adoption/baseline tracking query, not a threat detection. Returns all
sign-ins where a passkey authentication step succeeded — used to track
passwordless/passkey rollout adoption across the tenant rather than to
flag malicious activity.

## Hypothesis
Not applicable — this isn't built on a suspicious-behavior hypothesis.
It exists to answer a rollout/adoption question (how much of the tenant
is actually using passkeys) rather than to detect anything.

## Threat intelligence context
Not applicable — this is an adoption-metrics query, not a detection.

## Query

**Sentinel**
```kusto
SigninLogs
| mv-expand todynamic(AuthenticationDetails)
| where AuthenticationDetails.succeeded == true
    and AuthenticationDetails.authenticationMethod contains "passkey"
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## What a hit looks like
Not applicable — every row here is a normal, successful passkey sign-in.
Use aggregate counts over time to track rollout progress, not
individual rows for triage.

## False positive notes
Not applicable — there's no "false positive" concept for an adoption
metric; every match is exactly what it claims to be.

## Detection blind spots
Not applicable in the security-detection sense. As an adoption metric,
it only counts successful passkey authentications — it says nothing
about users who have passkeys registered but haven't used them, or about
adoption trend over time without additional aggregation on top of this
query.

## Validation
Not applicable — this is a metrics query, not a behavior-based detection
with an attack to simulate.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/passkey_auth_success.kql
