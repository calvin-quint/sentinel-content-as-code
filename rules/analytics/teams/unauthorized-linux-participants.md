---
id: unauthorized-linux-participants
title: Unauthenticated Linux Participants in Teams Meetings
tactic: Collection, Initial Access
technique: T1119, T1199
sub_technique_name: Automated Collection / Trusted Relationship (meeting-link abuse)
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
  id: 7cca4dab-452b-4489-a774-59a4295abdf4
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
  - InitialAccess
  relevantTechniques:
  - T1119
  - T1199
---

# Unauthenticated Linux Participants in Teams Meetings

## Summary
Near-real-time (15-minute window) detection of Teams meetings where
`HasUnauthenticatedUsers` is true and a participant's client OS is
Linux — an unauthenticated join from a Linux fingerprint is consistent
with a scripted/bot participant slipping in via a shared meeting link
rather than a genuine guest attendee. Complementary signal to
[`activity_from_amazon_isp_on_linux_clients.md`](activity_from_amazon_isp_on_linux_clients.md),
which flags Linux clients via ISP rather than the unauthenticated-
participant flag.

## Hypothesis
A genuine external guest joining a Teams meeting unauthenticated
(no org account) is normally doing so from a standard consumer OS/
client, not a Linux fingerprint — that combination is more consistent
with a scripted participant (a scraping/recording bot exploiting an
openly shared meeting link) than with a real human guest.

## Threat intelligence context
No named actor, malware family, or campaign — targets meeting-link
abuse by automated participants generally.

## Query

**Sentinel**
```kusto
CloudAppEvents
| where TimeGenerated >= ago(15m)
| where Application contains "Teams"
| extend Raw = parse_json(RawEventData)
| mv-expand ep = Raw.ExtraProperties
| extend ParticipantInfo = parse_json(tostring(Raw.ParticipantInfo))
| extend EPKey = tostring(ep.Key), EPValue = tostring(ep.Value)
| extend HasUnauthenticatedUsers = tostring(ParticipantInfo.HasUnauthenticatedUsers)
| where HasUnauthenticatedUsers == "true"
| where EPKey == "OsName" and EPValue == "linux"
```
(No Defender XDR variant — `CloudAppEvents` is a Sentinel/Defender for
Cloud Apps table.)

## What a hit looks like
A meeting flagged `HasUnauthenticatedUsers: true` with a Linux-
fingerprinted participant inside the 15-minute window. Identify the
meeting organizer and whether the meeting link was shared externally
(email, public channel) in a way that could explain an unexpected guest.

## False positive notes
Legitimate external guests occasionally do join from Linux desktop
environments — this isn't proof of a bot on its own, just a stronger-
than-baseline signal. Cross-reference against
[`activity_from_amazon_isp_on_linux_clients.md`](activity_from_amazon_isp_on_linux_clients.md)
for corroborating AWS-hosted infrastructure before escalating.

## Detection blind spots
The 15-minute window is designed for near-real-time triage, not
historical hunting — a longer lookback query would be needed to review
past meetings. Only catches unauthenticated Linux participants
specifically; an authenticated (compromised or complicit) internal
account running a scripted client, or a non-Linux scripted client,
produces no signal here.

## Validation
No public Atomic Red Team test applies — this is Teams/SaaS-specific
behavior, not a technique ART models. Validate manually: join a test
Teams meeting as an unauthenticated guest from a Linux client and
confirm the rule fires within the 15-minute window.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/teams/unauthorized_linux_participants.kql (renamed from source's `ununauth_linux_participants.kql` typo)
- MITRE ATT&CK: [T1119](https://attack.mitre.org/techniques/T1119/) (Automated Collection), [T1199](https://attack.mitre.org/techniques/T1199/) (Trusted Relationship)
