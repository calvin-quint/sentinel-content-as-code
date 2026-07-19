---
id: user-email-attachments-lookup
title: User Email Attachments Sent
tactic: null
technique: null
sub_technique_name: null
severity: low
confidence: high
status: production
platforms:
- defender_xdr
- sentinel
data_sources:
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
analytics_rule: null
---

# User Email Attachments Sent

## Summary
Parameterized lookup, not a standalone detection. Given a `$UPN`, lists
every email with an attachment sent by that user. Used to build an
outbound-attachment timeline during an insider-threat or account-
compromise investigation.

## Hypothesis
Not applicable — this is an investigative lookup rather than a
suspicious-behavior detection. It exists to answer "what has this
already-flagged user been emailing out" once an investigation is
underway, not to surface suspicious activity on its own.

## Threat intelligence context
No fixed named threat — used generically once an account is already
under investigation for any reason.

## Query

**Defender XDR / Sentinel**
```kusto
EmailEvents
| where SenderFromAddress contains "$UPN"
| where AttachmentCount > 0
```
Substitute the actual UPN under investigation for `$UPN`. Same query
works unchanged in both — `EmailEvents` is shared schema between the
Defender XDR portal and Sentinel.

## What a hit looks like
A full list of outbound emails with attachments from the user — cross-
reference recipients and subjects for anything inconsistent with their
normal role, and pull actual attachment content/hashes separately if a
specific email warrants deeper review.

## False positive notes
Not applicable — targeted lookup against an already-identified account,
not a broad detection subject to noise.

## Detection blind spots
Only catches attachments, not other exfiltration channels (links to
cloud storage, inline pasted content, BCC to a personal address handled
by other rules in this folder). `AttachmentCount > 0` also doesn't
distinguish attachment size or type — a single small signature image
counts the same as a large sensitive document dump.

## Validation
Not applicable — this is a lookup template, not an auto-firing detection
with a behavior to simulate.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/user_email_attachments_lookup.kql
