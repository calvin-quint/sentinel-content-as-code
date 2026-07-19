---
id: admin-account-recovery-initiated
title: 1Password Admin-Initiated Account Recovery
tactic: Persistence, Privilege Escalation
technique: T1098
sub_technique_name: Account Manipulation
severity: medium
confidence: medium
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
  id: c21fb0b2-0356-4fdd-9df0-78e7c71dc9e2
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
  - Persistence
  - PrivilegeEscalation
  relevantTechniques:
  - T1098
  entityMappings:
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: source_ip
---

# 1Password Admin-Initiated Account Recovery

## Summary
Flags an administrator initiating password/account recovery on behalf of
another user — legitimate for offboarding/lockout support, but also the
mechanism a compromised admin account or malicious insider would use to
seize control of a target's vault.

## Hypothesis
Legitimate admin-initiated recovery is infrequent and should always map
to an open helpdesk ticket. An event with no corresponding ticket,
unusual timing, or targeting a high-privilege account's vault is the
signal worth investigating — the rule surfaces every instance rather
than trying to score anomaly itself, on the assumption that recovery
events are rare enough to review individually.

## Threat intelligence context
No named actor, malware family, or campaign — this is a generic
insider/compromised-admin detection, not threat-intel-driven.

## Query

**Sentinel**
```kusto
OnePasswordEventLogs_CL
| where action == "beginr"
| where object_type == "user"
| extend
    admin_name = tostring(parse_json(actor_details).name),
    admin_email = tostring(parse_json(actor_details).email),
    target_name = tostring(parse_json(object_details).name),
    target_email = tostring(parse_json(object_details).email),
    source_ip = tostring(parse_json(session).ip)
| project
    TimeGenerated,
    admin_name,
    admin_email,
    target_name,
    target_email,
    source_ip
```
(No Defender XDR variant — `OnePasswordEventLogs_CL` is a Sentinel custom
log table fed by 1Password's event API, not a Defender/M365 source.)

## What a hit looks like
An `admin_name`/`admin_email` initiating recovery against a `target_name`
— cross-reference the source IP/geography against the admin's normal
working pattern, and confirm an open helpdesk ticket exists for the
target user before closing this out.

## False positive notes
Real offboarding and lockout-support workflows produce this event
legitimately and often. This rule has no way to distinguish a ticketed
recovery from an unticketed one on its own — that correlation has to
happen against the ticketing system, not this query.

## Detection blind spots
Only fires on the `"beginr"` action name — if 1Password renames or
versions its action taxonomy, this rule silently stops matching. No
volume/frequency threshold: a single event always fires by design, which
means a scripted or mass-recovery scenario across many admins in a short
window looks identical to one isolated legitimate case here — nothing in
this query would rank one as more urgent than the other.

## Validation
No public Atomic Red Team test applies — 1Password isn't in ART's
covered surface (it targets OS/cloud-platform techniques, not individual
SaaS password managers). Validate manually: trigger a real admin-recovery
action against a test account in a non-production 1Password tenant and
confirm `OnePasswordEventLogs_CL` ingests it and the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/1password/admin_account_recovery_initiated.kql
- MITRE ATT&CK: [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation)
