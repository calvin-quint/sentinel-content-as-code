---
id: antivirus-detections
title: Defender Antivirus Detections
tactic: Execution
technique: null
sub_technique_name: null
severity: low
confidence: high
status: production
platforms:
- defender_xdr
- sentinel
data_sources:
- DeviceEvents
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

# Defender Antivirus Detections

## Summary
Raw feed of Microsoft Defender Antivirus detection events. Used as a
base lookup/enrichment source for other rules and manual triage rather
than a standalone alert — pair with the specific malware family/behavior
to map an exact technique.

## Hypothesis
Not applicable in the usual sense — this isn't an anomaly detector, it's
a raw event feed. Its value is as a join/enrichment source for other
rules (e.g., correlating an AV hit against the same device's process
tree or network activity around the same time) and as a starting point
for manual triage, not as something to act on row-by-row in isolation.

## Threat intelligence context
No fixed named threat — the specific malware family/threat named in each
event (`ThreatName` field) varies per detection and should be looked up
individually when triaging a hit.

## Query

**Defender XDR / Sentinel**
```kusto
DeviceEvents
| where ActionType == "AntivirusDetection"
```
(Same query works unchanged in both — `DeviceEvents` and `ActionType`
are shared schema between the Defender XDR portal and Sentinel.)

## What a hit looks like
Not a single "hit" pattern — this is a feed. Look at volume/frequency
per device (a spike suggests active infection rather than a one-off),
and the `ThreatName` field to identify what Defender actually classified
it as before deciding on further action.

## False positive notes
Not really applicable to a raw AV-detection feed — Defender's own
classification is the filter here. The noise concern is volume, not
false positives: routine PUA/PUP detections on end-user devices can make
this feed noisy if reviewed unfiltered.

## Detection blind spots
Only surfaces what Defender AV itself already classified and blocked/
flagged — it says nothing about anything that evaded AV signature/
behavioral detection entirely. This is an enrichment source, not a
detection in its own right; treat it as one input into a broader
investigation, not a complete picture.

## Validation
Not applicable — this is a raw telemetry feed, not a behavior-based
detection with a specific attack to simulate.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/endpoint/antivirus_detections.kql
