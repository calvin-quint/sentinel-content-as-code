---
id: non-user-actors-amazon-isp
title: Non-User Actor in Teams from Amazon ISP
tactic: Collection
technique: T1119
sub_technique_name: Automated Collection
severity: medium
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- CloudAppEvents
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
  id: fa27e96d-4090-4627-9f8f-974539de7f5b
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
  - Collection
  relevantTechniques:
  - T1119
---

# Non-User Actor in Teams from Amazon ISP

## Summary
Narrows [`activity_from_amazon_isp_on_linux_clients.md`](activity_from_amazon_isp_on_linux_clients.md)
down to confirmed non-human actors: Teams activity where the acting
entity's `Role` is "Actor" but its `Type` is not "User" (a bot/
application identity, not a person), sourced from AWS infrastructure —
the strongest signal that an automated bot, rather than an employee on a
cloud VPN, is operating inside a meeting.

## Hypothesis
The broader ISP/OS-fingerprint rule can't distinguish a real employee
using an AWS-hosted Linux VM as a personal jump box from an actual bot.
Checking the activity object's own `Type` field for "not User" removes
that ambiguity directly — Teams itself is reporting the actor as a
non-human identity, not just exhibiting bot-like network characteristics.

## Threat intelligence context
No named actor, malware family, or campaign — targets the general
pattern of unauthorized bot/application actors in meetings.

## Query

**Sentinel**
```kusto
CloudAppEvents
| where Application contains "Teams"
| where ISP contains "Amazon"
| extend ParsedObjects = parse_json(ActivityObjects)
| mv-expand obj = ParsedObjects
| extend Role = tostring(obj.Role), Type = tostring(obj.Type)
| where Role == "Actor" and Type != "User"
```
(No Defender XDR variant — `CloudAppEvents` is a Sentinel/Defender for
Cloud Apps table.)

## What a hit looks like
A confirmed non-`User`-type actor performing activity in a Teams
meeting from AWS infrastructure. Identify which meeting it joined and
who scheduled/hosted it, then check for a sanctioned reason (an approved
bot integration) before treating it as unauthorized.

## False positive notes
Sanctioned bot integrations (approved meeting-recording or scheduling
bots) that legitimately run on AWS infrastructure will also have
`Type != "User"` and will match here. Maintain an allowlist of approved
bot application IDs to exclude rather than loosening the Role/Type
check.

## Detection blind spots
Same ISP/OS scoping limits as the broader rule — a non-user actor hosted
outside AWS produces no signal. Also depends on Teams correctly
reporting `Type` for the actor; a bot using a compromised or spoofed
user identity (rather than its own application identity) would appear
as `Type == "User"` and evade this specific check, though it might still
be caught by the OS/ISP-fingerprint rule.

## Validation
No public Atomic Red Team test applies — this is Teams/SaaS-specific
behavior, not a host-level technique ART models. Validate manually: have
a bot/application identity (not a user account) join a test Teams
meeting from AWS-hosted infrastructure and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/teams/non_user_actors_amazon_isp.kql
- MITRE ATT&CK: [T1119](https://attack.mitre.org/techniques/T1119/) (Automated Collection)
