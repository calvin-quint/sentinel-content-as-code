---
id: activity-from-amazon-isp-on-linux-clients
title: Teams Activity from Amazon ISP on Linux Clients
tactic: Collection
technique: T1119
sub_technique_name: Automated Collection
severity: low
confidence: low
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
  id: 0767db84-336e-4872-a470-a111cbd22315
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
  entityMappings:
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: ISP-derived source IP (RawEventData)
---

# Teams Activity from Amazon ISP on Linux Clients

## Summary
Broadest of the Teams-bot family of rules — flags any Microsoft Teams
activity originating from an AWS-hosted IP (`ISP` contains "Amazon") on
a Linux client. This is the network/OS fingerprint of a cloud-hosted
meeting bot rather than a genuine employee endpoint, and feeds the more
targeted [non-user-actor](non_user_actors_amazon_isp.md) and
[AI-transcription](non_user_ai_transcription_activity.md) variants in
this folder.

## Hypothesis
Genuine employees overwhelmingly join Teams from Windows/macOS/mobile
clients on residential or corporate ISPs, not Linux clients on AWS
infrastructure. That combination — Linux OS fingerprint plus AWS-hosted
egress IP — is a much stronger indicator of an automated, cloud-hosted
bot than of a real person, regardless of what that bot turns out to be
doing.

## Threat intelligence context
No named actor, malware family, or campaign — this targets the general
pattern of cloud-hosted meeting bots/scrapers, not a specific threat.

## Query

**Sentinel**
```kusto
CloudAppEvents
| where Application contains "Teams"
| where ISP contains "Amazon"
| extend Raw = parse_json(RawEventData)
| mv-expand ep = Raw.ExtraProperties
| extend EPKey = tostring(ep.Key), EPValue = tostring(ep.Value)
| where EPKey == "OsName" and EPValue == "linux"
```
(No Defender XDR variant — `CloudAppEvents` is a Sentinel/Defender for
Cloud Apps table.)

## What a hit looks like
Any row is worth a quick look — identify which meeting/user account the
activity is tied to and whether a legitimate AWS-hosted Linux client
(e.g., a sanctioned automation account) explains it before escalating to
the narrower rules in this folder.

## False positive notes
Legitimate developer VMs, CI/CD runners, or sanctioned automation
accounts that happen to interact with Teams from AWS-hosted Linux boxes
will match this broad rule. This is intentionally the noisiest rule in
the family — it exists as a wide net, with the other three rules in this
folder narrowing down to higher-confidence subsets.

## Detection blind spots
Only catches AWS-hosted bots specifically (`ISP contains "Amazon"`) — a
bot hosted on Azure, GCP, or a residential/VPS provider produces no
signal here at all. Also only catches Linux clients; a bot running a
Windows or macOS-fingerprinted client evades this rule entirely.

## Validation
No public Atomic Red Team test applies — this is Teams/SaaS-specific
behavior, not a host-level technique ART models. Validate manually: join
a test Teams meeting from a Linux VM hosted on AWS and confirm the rule
fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/teams/activity_from_amazon_isp_on_linux_clients.kql
- MITRE ATT&CK: [T1119](https://attack.mitre.org/techniques/T1119/) (Automated Collection)
