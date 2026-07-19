---
id: meeting-links-to-ai-services
title: Meeting Invite Links Sent to AI Transcription Services
tactic: Collection, Exfiltration
technique: T1119, T1567
sub_technique_name: Automated Collection / Exfiltration Over Web Service
severity: medium
confidence: high
status: production
platforms:
- defender_xdr
- sentinel
data_sources:
- EmailUrlInfo
- EmailEvents
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
  id: bb62fe99-04af-41cc-83dd-a1e3c4adbeaa
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
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: Address
      columnName: SenderFromAddress
---

# Meeting Invite Links Sent to AI Transcription Services

## Summary
Email-based companion to the Teams-bot detections in
[`teams/`](../teams/README.md) — catches the invite step rather than the
bot's in-meeting activity. Flags outbound emails containing a Teams/Zoom
meeting join link where the recipient address belongs to an AI note-
taking service (otter.ai, read.ai): someone forwarding or CC'ing a
meeting invite so the bot auto-joins.

## Hypothesis
A meeting join link (Teams or Zoom) sent directly to an AI transcription
service's own email address is a deliberate invitation, not incidental —
these services join meetings specifically by being added as an invitee
or forwarded the link, so catching the email step surfaces the intent
before the bot even joins, complementing the in-meeting detections in
the `teams/` folder.

## Threat intelligence context
No named actor or campaign — targets the general pattern of
unsanctioned shadow-IT AI notetaker tools, same category as the
`teams/` bot-detection family.

## Query

**Defender XDR / Sentinel**
```kusto
let meetingUrls = dynamic(["teams.microsoft.com/l/meetup-join", "zoom.us"]);
let targetDomains = dynamic(["otter.ai", "read.ai"]);
EmailUrlInfo
| where Url has_any(meetingUrls)
| join kind=inner (
    EmailEvents
    | where RecipientEmailAddress has_any(targetDomains)
    | project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, Timestamp
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url
| order by Timestamp desc
```
(Same query works unchanged in both — `EmailUrlInfo`/`EmailEvents` are
shared schema between the Defender XDR portal and Sentinel.)

## What a hit looks like
A `SenderFromAddress` sending a meeting link directly to an
`otter.ai`/`read.ai` address. Identify the meeting and its subject
matter to assess what content the bot may capture.

## False positive notes
If the org has formally sanctioned one of these services, every
legitimate use will match. Exclude by specific approved sender/use case
rather than removing the domain from `targetDomains`, so an
unsanctioned second instance is still caught.

## Detection blind spots
Only catches these two named services and two meeting-platform URL
patterns — a different AI notetaker, a different meeting platform, or a
bot joining via a shared link posted in chat (rather than emailed
directly) evades this rule. Complements but doesn't replace the
in-meeting `teams/` detections, which catch the bot's actual presence
regardless of how it was invited.

## Validation
No confirmed Atomic Red Team test identified — this is an M365/SaaS-
specific shadow-IT pattern, not a technique ART models. Validate
manually: send a test meeting link to an otter.ai or read.ai address
from a lab tenant and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/meeting_links_to_ai_services.kql
- MITRE ATT&CK: [T1119](https://attack.mitre.org/techniques/T1119/) (Automated Collection), [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service)
