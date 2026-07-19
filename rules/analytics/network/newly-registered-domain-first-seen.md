---
id: newly-registered-domain-first-seen
title: Newly Registered / First-Seen Domain Detection
tactic: Resource Development
technique: T1583.001, T1584.001
sub_technique_name: Acquire/Compromise Infrastructure - Domains
severity: medium
confidence: low
status: production
platforms: [sentinel]
data_sources: [_Im_Dns]
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
analytics_rule:
  id: d3cd4ded-31ca-4fd6-93ec-0330b34eede8
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [ResourceDevelopment]
  relevantTechniques: [T1583.001, T1584.001]
  entityMappings:
    - entityType: DNS
      fieldMappings:
        - identifier: DomainName
          columnName: DnsQuery
  incidentConfiguration:
    createIncident: true
    groupingConfiguration:
      enabled: true
      reopenClosedIncident: false
      lookbackDuration: PT5H
      matchingMethod: AllEntities
  eventGroupingSettings:
    aggregationKind: SingleAlert
owner: calvin
last_reviewed: "2026-07-19"
---

# Newly Registered / First-Seen Domain Detection

## Summary
Flags domains queried by the environment that have no query history in
the prior 30-day baseline window — a practical proxy for "newly
registered/newly seen" without requiring a WHOIS/RDAP feed. Companion
rule to [`lookalike-domain-detected.md`](lookalike-domain-detected.md),
which was originally the second half of this same hunting query before
being split out (a Sentinel scheduled rule can only emit one result set,
and the two detections use unrelated logic and severities).

## Hypothesis
A domain with zero query history across a 30-day baseline that suddenly
appears is either a genuinely new, legitimate service the environment
hasn't touched before, or infrastructure that's new to *everyone*
because it was only just stood up — the low-query-volume filter
(`QueryCount < 5`) specifically targets the latter: low-volume first
contact reads as reconnaissance/beaconing rather than a bulk CDN rollout
that would show high query volume from the start.

## Threat intelligence context
No named actor, malware family, or campaign — a generic infrastructure-
acquisition detection. Directly complementary to a domain-monitoring
early-warning approach (Certificate Transparency + brand-permutation
watching) — this rule is the *internal* signal (something in the
environment queried a brand-new domain), where a CT-log watcher would be
the *external* signal (a brand-new domain matching your brand exists at
all, before anyone inside the org has touched it).

## Query

**Sentinel**
```kusto
let baselineWindow = 30d;
let detectionWindow = 1d;
let baselineDomains =
    _Im_Dns(starttime = ago(baselineWindow + detectionWindow), endtime = ago(detectionWindow))
    | distinct DnsQuery;
_Im_Dns(starttime = ago(detectionWindow), endtime = now())
| where DnsQuery !in (baselineDomains)
| where isnotempty(DnsQuery)
| summarize FirstSeen = min(TimeGenerated), QueryCount = count(),
            Devices = make_set(SrcIpAddr, 10)
    by DnsQuery
| where QueryCount < 5  // low-volume first contact is more suspicious than a bulk CDN rollout
| project FirstSeen, DnsQuery, QueryCount, Devices
| order by FirstSeen desc
```
(No Defender XDR variant — this uses the ASIM DNS normalization
parser `_Im_Dns`, a Sentinel-specific parser abstraction; swap for the
underlying source table, e.g. `CommonSecurityLog` or
`DeviceNetworkEvents`, if ASIM parsers aren't deployed in the
workspace.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Resource Development — T1583.001, T1584.001 |
| Entity mappings | `DNS.DomainName = DnsQuery` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DnsQuery` with `FirstSeen` in the last day, low `QueryCount`, and a
small `Devices` set (one or two hosts querying it, not org-wide). Pivot
to those devices' broader activity around `FirstSeen` for context.

## False positive notes
Legitimately new SaaS vendors and CDN edge nodes are the main source of
noise — a new vendor rollout or a CDN provider rotating edge hostnames
can produce first-seen domains with low initial query volume that look
identical to something suspicious. This rule is a triage feed, not a
confirmed-bad list.

## Detection blind spots
Only covers domains actually *queried by the environment* — this says
nothing about phishing/lookalike infrastructure that exists but hasn't
been contacted yet (see `lookalike-domain-detected.md` for that angle,
and an external CT-log watcher for catching it before any internal
contact happens at all). A domain resolved via DNS-over-HTTPS to a
resolver outside what `_Im_Dns` ingests would also produce no signal.
The 30-day baseline also means an environment younger than 30 days has
an unreliable/overly-noisy baseline.

## Validation
No confirmed Atomic Red Team test identified — DNS-baseline anomaly
detection isn't a technique ART simulates (it requires real, sustained
tenant DNS query history to build a baseline against, not a single host
action). Validate manually: query a domain that hasn't appeared in the
last 30 days from a lab device and confirm the rule fires.

## References
- MITRE ATT&CK: [T1583.001](https://attack.mitre.org/techniques/T1583/001/) / [T1584.001](https://attack.mitre.org/techniques/T1584/001/) (Acquire/Compromise Infrastructure: Domains)
