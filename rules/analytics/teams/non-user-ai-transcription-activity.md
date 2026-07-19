---
id: non-user-ai-transcription-activity
title: Non-User AI Transcription Bot Activity in Teams
tactic: Collection, Exfiltration
technique: T1119, T1567
sub_technique_name: Automated Collection / Exfiltration Over Web Service
severity: high
confidence: high
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
  id: 93230dc5-1080-486a-88d0-b60aae01f20b
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
  - Exfiltration
  relevantTechniques:
  - T1119
  - T1567
---

# Non-User AI Transcription Bot Activity in Teams

## Summary
The most specific rule in the Teams-bot family — a non-user actor from
AWS infrastructure posting message URLs referencing Otter.ai or Read.ai.
Confirms an unsanctioned AI note-taking bot has joined a meeting and is
actively pushing meeting content to a third-party SaaS transcription
service, a direct data-exfiltration path if the meeting covers sensitive
topics.

## Hypothesis
A non-user actor from AWS infrastructure is already suspicious on its
own (see [`non_user_actors_amazon_isp.md`](non_user_actors_amazon_isp.md)),
but confirming it's posting URLs to a named third-party transcription
service removes any ambiguity about intent — this isn't a generic
automation identity, it's specifically shipping meeting content off to
an external SaaS product the org hasn't sanctioned.

## Threat intelligence context
No named actor or campaign — targets a known category of unsanctioned
shadow-IT AI notetaker tools (Otter.ai, Read.ai), not a specific threat
actor.

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
| extend ParsedRaw = parse_json(RawEventData)
| extend MessageURLs = tostring(ParsedRaw.MessageURLs)
| where MessageURLs has "otter.ai" or MessageURLs has "read.ai"
```
(No Defender XDR variant — `CloudAppEvents` is a Sentinel/Defender for
Cloud Apps table.)

## What a hit looks like
A confirmed non-user actor posting an Otter.ai or Read.ai URL into a
meeting's message stream. Treat as confirmed shadow-IT data exfiltration
— identify the meeting, its participants, and its subject matter to
scope what content may have left the org's control.

## False positive notes
If the org has formally sanctioned Otter.ai or Read.ai for note-taking,
every legitimate use will match this rule. In that case, exclude the
specific approved bot's application ID rather than removing the
`otter.ai`/`read.ai` string match, so an unsanctioned second instance or
a different AI notetaker is still caught.

## Detection blind spots
Only catches these two named transcription services — any other AI
notetaker (Fireflies, Fathom, Gong, etc.) or a bot hosted outside AWS
evades this rule entirely. It also depends on the bot posting a
detectable URL in `MessageURLs`; a notetaker that captures audio/video
directly without posting a chat link produces no signal here.

## Validation
No public Atomic Red Team test applies — this is Teams/SaaS-specific
shadow-IT behavior, not a technique ART models. Validate manually: have
an Otter.ai or Read.ai bot join a test Teams meeting from AWS-hosted
infrastructure and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/teams/non_user_ai_transcription_activity.kql
- MITRE ATT&CK: [T1119](https://attack.mitre.org/techniques/T1119/) (Automated Collection), [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service)
