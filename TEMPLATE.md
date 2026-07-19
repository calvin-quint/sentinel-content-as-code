---
id: ""                        # kebab-case, matches filename
title: ""
tactic: ""                     # MITRE ATT&CK tactic(s), human-readable, comma-separated
technique: ""                   # e.g. T1071.004 — comma-separate if multiple
sub_technique_name: ""
severity: ""                    # low | medium | high | critical (narrative — critical maps to ARM "High" at deploy time, ARM has no Critical enum)
confidence: ""                   # low | medium | high
status: draft                     # draft | testing | production | deprecated (content lifecycle, distinct from analytics_rule.status)
platforms: []                      # defender_xdr and/or sentinel — table names differ (Timestamp vs TimeGenerated)
data_sources: []                    # e.g. [DeviceNetworkEvents, DnsEvents]
sigma_source: null                    # path to sigma/<category>/<rule-name>.yml if this rule is Sigma-sourced; null if KQL-first
threat_intel:
  family: null                        # malware/tool family this maps to, if any
  actor: null                          # attributed actor/group, if known
  campaign: null
  first_seen: null
  references: []
  yara_rule: null                       # path to yara/<family>/<rule-name>.yar, if a companion artifact-ID rule exists
validated:
  atomic_test: null                     # Atomic Red Team test ID, if one exists
  atomic_test_url: null                  # direct link to the test in redcanaryco/atomic-red-team
  lab_ref: null                          # path in offsec-lab where it was run
  last_run: null
  result: null                            # fired as expected | no hits | false positive
analytics_rule:                             # present only for rules deployed as a Sentinel Scheduled Analytics Rule.
                                              # Fields here match schemas/analytics-rule.schema.json almost verbatim —
                                              # name/description/severity/query are NOT duplicated here; rule_transform.py
                                              # derives them from title/Summary/severity(capitalized)/the Sentinel query block.
  id: ""                                       # GUID — generate once with uuidgen, never change (changing creates a new rule)
  kind: Scheduled
  status: Available                              # Available | InPreview — ARM lifecycle metadata, not sent to the API
  enabled: true
  queryFrequency: ""                              # ISO 8601, e.g. PT1H
  queryPeriod: ""
  triggerOperator: ""                              # gt | lt | eq | ne
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: []                                       # exact ARM enum values, e.g. [CredentialAccess, InitialAccess]
  relevantTechniques: []                             # e.g. [T1078.004]
  entityMappings: []                                  # exact ARM shape — see schemas/analytics-rule.schema.json
  incidentConfiguration: {}
  eventGroupingSettings: {}
  customDetails: {}
  alertDetailsOverride: {}
  requiredDataConnectors: []                            # documentation-only metadata, not sent to the API
owner: ""
last_reviewed: ""
---

# {title}

## Summary
One or two sentences: what this detects and why it matters.

## Hypothesis
The assumption this detection is built on — what normal looks like, and
what specific deviation is being treated as suspicious. State it as a
claim that could be wrong, not a description of the query.

## Threat intelligence context
Only meaningful when `threat_intel.family` or `threat_intel.actor` is
set. What is this behavior tied to — a named malware family, a tracked
actor, a specific campaign, a disclosed technique/CVE? Cite the source.
If this is a generic or statistical detection with no specific named-
threat tie, say so explicitly rather than leaving the section implicit.

## Query

**Defender XDR**
```kusto
// uses Timestamp
```

**Sentinel**
```kusto
// uses TimeGenerated — this is the block rule_transform.py extracts for deployment
```
(Omit whichever platform doesn't apply — leave one block if `platforms`
has a single entry. If only a Defender XDR block exists, this rule
cannot be deployed as a Sentinel analytics rule — leave `analytics_rule`
unset.)

## Analytics rule configuration
Only present when `analytics_rule` is filled in — a human-readable
summary table of the frontmatter's deploy config (frequency/period/
suppression, entity mappings, custom details, what this replaces if
anything).

## What a hit looks like
Describe the shape of a true-positive result — which fields matter,
what an analyst should check next.

## False positive notes
Known benign causes for this to fire, and how to tell them apart from
a real hit.

## Detection blind spots
What this detection does *not* catch — the attacker behavior that would
slip past it even though it's in scope for this technique. Distinct from
false positives: this is about coverage gaps, not noise.

## Validation
How this was tested — which Atomic Red Team test simulated the behavior,
where in `offsec-lab` that run lives, when it was last run, and what
happened. If this hasn't been validated against a live attack yet, say so
rather than omitting the section — empirical production tuning is not the
same thing as attack-simulation validation; state which one (if either)
has actually happened. Link the specific Atomic Red Team test
(`atomic_test_url`), not just its ID.

## References
- Links to threat intel reports, ATT&CK pages, vendor writeups, CVEs.
