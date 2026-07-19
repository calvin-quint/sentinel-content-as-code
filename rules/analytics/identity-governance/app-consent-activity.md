---
id: app-consent-activity
title: OAuth Application Consent Activity
tactic: Initial Access, Persistence
technique: T1528, T1098.001
sub_technique_name: Steal Application Access Token / Additional Cloud Credentials
severity: medium
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
  id: 0881f839-c11d-46c8-b6a3-f5d63bf8808b
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
  - Persistence
  relevantTechniques:
  - T1528
  - T1098.001
---

# OAuth Application Consent Activity

## Summary
Baseline/hunting query — returns all OAuth application consent grants
tenant-wide, unfiltered. Feeds illicit-consent-grant hunting: a user
tricked into approving a malicious app's permission scopes gives an
attacker durable, MFA-independent access to mail/files without ever
touching the user's password.

## Hypothesis
Not an anomaly detector on its own — every consent event is legitimate
until reviewed. The hypothesis this query supports is that consent
grants are infrequent enough, and illicit-consent-grant attacks
consequential enough, that a human reviewing every grant tenant-wide is
worthwhile rather than trying to pre-filter which ones look suspicious.

## Threat intelligence context
No named actor, malware family, or campaign — a baseline/hunting feed
for the general illicit-consent-grant attack class, not tied to one
incident.

## Query

**Sentinel**
```kusto
CloudAppEvents
| where ActionType == "Consent to application."
```
(No Defender XDR variant — `CloudAppEvents` is a Sentinel/Defender for
Cloud Apps table; while a related view exists in the Defender XDR
portal, this exact query form targets the Sentinel table directly.)

## What a hit looks like
Every row is a real consent event — review the granted scopes and the
requesting app's publisher/verification status. Scopes like
`Mail.Read`, `Files.ReadWrite.All`, or `Directory.Read.All` granted to an
unverified or unfamiliar publisher are the ones to chase first.

## False positive notes
This query returns everything, so by design the majority of results will
be legitimate — approved business app installs, IT-sanctioned
integrations, and routine user consent to known Microsoft first-party
apps. This isn't a tuning problem to fix; it's an inherent property of a
baseline feed meant for human review, not a threshold-based alert.

## Detection blind spots
Says nothing about the requested scopes' actual risk level, the
requesting app's publisher verification status, or how many other users
have consented to the same app — an analyst has to pull that context
separately for each row. A tenant-wide admin consent policy that
pre-approves certain app categories may also suppress the individual
consent events this query expects to see.

## Validation
Atomic Red Team has coverage for the related T1098.001 (Additional Cloud
Credentials — adding credentials to an existing app/service principal),
but that's a distinct action from a user consenting to a new malicious
app's OAuth scopes, which isn't confirmed as covered by a specific ART
test. Validate manually: register a test app with broad Mail/Files
scopes in a lab tenant, consent to it as a test user, and confirm the
event appears.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity-governance/app_consent_activity.kql
- MITRE ATT&CK: [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token), [T1098.001](https://attack.mitre.org/techniques/T1098/001/) (Additional Cloud Credentials)
