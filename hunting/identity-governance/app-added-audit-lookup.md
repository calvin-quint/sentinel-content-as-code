---
id: app-added-audit-lookup
title: "App Registration Added \u2014 Audit Lookup"
tactic: Persistence
technique: T1136.003
sub_technique_name: Create Account - Cloud Account
severity: low
confidence: high
status: production
platforms:
- sentinel
data_sources:
- AuditLogs
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

# App Registration Added — Audit Lookup

## Summary
Parameterized lookup, not a standalone auto-firing detection. Given an
`$AppID`, returns the Entra ID audit event recording when that
application was registered. Used during investigation to pin down who
created a suspicious app registration and when, ahead of building a
broader OAuth-abuse timeline.

## Hypothesis
Not applicable in the usual sense — this is an investigative lookup
rather than a query built on a suspicious-behavior hypothesis. It exists
to answer one specific question fast (who registered this app, and
when) once an app ID is already flagged as worth investigating by
another rule (e.g., [`app_consent_activity.md`](app_consent_activity.md)).

## Threat intelligence context
No named actor, malware family, or campaign — this is a generic
investigative tool, not a threat-intel-driven detection.

## Query

**Sentinel**
```kusto
AuditLogs
| where OperationName == "Add application"
| where TargetResources contains "$AppID"
```
Substitute the actual application ID under investigation for `$AppID`
before running.

(No Defender XDR variant — `AuditLogs` is a Sentinel/Entra ID table with
no Defender XDR portal equivalent.)

## What a hit looks like
A single audit event showing who registered the app and when — the
`InitiatedBy` field on the returned row is the actor to chase down next.

## False positive notes
Not applicable — this is a targeted lookup against a specific already-
identified app ID, not a broad detection subject to noise.

## Detection blind spots
Only finds the registration event itself — it says nothing about
whether the app's permission scopes are risky or whether users have
consented to it. Pair with `app_consent_activity.md` to get the full
picture of an OAuth-abuse timeline.

## Validation
Not applicable — this is a lookup template, not an auto-firing detection
with a behavior to simulate.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity-governance/app_added_audit_lookup.kql
- MITRE ATT&CK: [T1136.003](https://attack.mitre.org/techniques/T1136/003/) (Create Account: Cloud Account)
