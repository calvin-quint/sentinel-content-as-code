---
id: email-attachment-hash-lookup
title: Email Attachment Hash Lookup
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
- EmailAttachmentInfo
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

# Email Attachment Hash Lookup

## Summary
Parameterized lookup, not a standalone detection. Given a `$hash` and/or
`$NetworkMessageId`, locates every email carrying that attachment SHA256.
Used during incident triage to scope how widely a malicious or leaked
attachment circulated.

## Hypothesis
Not applicable — this is an investigative lookup rather than a
suspicious-behavior detection. It exists to answer "who else received
this exact file" once a hash is already known to matter, typically from
another detection or a threat-intel match.

## Threat intelligence context
No fixed named threat — the specific IOC being searched varies per
investigation.

## Query

**Defender XDR / Sentinel**
```kusto
EmailAttachmentInfo
| where SHA256 contains "$hash"
| where NetworkMessageId contains "$NetworkMessageId"
```
Substitute the actual hash and/or message ID under investigation.
`EmailAttachmentInfo` is shared schema between the Defender XDR portal
and Sentinel — same query works unchanged in both.

## What a hit looks like
Every matching row is a real recipient of the attachment — build a
distribution list from `RecipientEmailAddress`/similar fields to scope
exposure.

## False positive notes
Not applicable — targeted lookup against a specific already-identified
hash, not a broad detection subject to noise.

## Detection blind spots
Only finds the attachment by hash — a re-encoded, repackaged, or
password-protected version of the same malicious content with a
different hash won't match. Pair with threat-intel enrichment or a
broader content-based search if hash evasion is suspected.

## Validation
Not applicable — this is a lookup template, not an auto-firing detection
with a behavior to simulate.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/email_attachment_hash_lookup.kql
