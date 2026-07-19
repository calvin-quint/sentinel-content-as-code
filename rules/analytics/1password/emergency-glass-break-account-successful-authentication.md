---
id: emergency-glass-break-account-successful-authentication
title: 1Password Break-Glass Account Successful Authentication
tactic: Initial Access, Privilege Escalation
technique: T1078.004
sub_technique_name: Valid Accounts - Cloud Accounts
severity: critical
confidence: high
status: production
platforms:
- sentinel
data_sources:
- OnePasswordEventLogs_CL
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
  id: a3ef6edd-5afd-4e6c-81f3-330e000ba067
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
  - PrivilegeEscalation
  relevantTechniques:
  - T1078.004
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: target_user.email
---

# 1Password Break-Glass Account Successful Authentication

## Summary
Fires on any successful authentication to the emergency break-glass
admin account. This account exists solely for outage/lockout recovery
and should never be used in normal operations — any hit is a same-day
investigation, not a tuning candidate.

## Hypothesis
Unlike a statistical anomaly detection, this rule is a hard invariant:
the break-glass account has zero legitimate use outside a declared
outage or disaster-recovery event. There is no "normal" baseline to
compare against — any successful authentication to this specific
account, at any time, under any circumstances, is the thing being
detected.

## Threat intelligence context
No named actor, malware family, or campaign — this detects abuse of a
specific privileged account by design, not a threat-intel-driven
pattern.

## Query

**Sentinel**
```kusto
OnePasswordEventLogs_CL
| where tostring(target_user.email) =~ "breakglass-admin@contoso.com"
| where category == "success"
```
(No Defender XDR variant — `OnePasswordEventLogs_CL` is a Sentinel custom
log table fed by 1Password's event API, not a Defender/M365 source.)

## What a hit looks like
Any single row matters. Pull the source IP and geography from the
surrounding event payload and correlate against declared change-
management or disaster-recovery windows before treating it as
confirmed misuse.

## False positive notes
Scheduled credential-rotation tests or DR/BCP drills that intentionally
exercise the break-glass account will trigger this legitimately. Handle
those by pre-notifying the on-call window the drill covers, not by
excluding the account from the rule — an exclusion here defeats the
entire point of the detection.

## Detection blind spots
Hardcoded to one specific UPN (`breakglass-admin@contoso.com`). If the
account is renamed, credentials rotated to a new identity, or a second,
undocumented break-glass account exists, this rule silently stops
covering it. Also filters to `category == "success"` only — it does not
catch failed authentication attempts against the account, which could
indicate someone probing for it before a successful compromise.

## Validation
No public Atomic Red Team test applies — 1Password isn't in ART's
covered surface. Validate manually: authenticate to a test break-glass
account in a non-production 1Password tenant and confirm the event
ingests and the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/1password/emergency_glass_break_account_successful_authentication.kql
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
