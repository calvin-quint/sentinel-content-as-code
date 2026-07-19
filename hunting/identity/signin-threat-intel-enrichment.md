---
id: signin-threat-intel-enrichment
title: Sign-in Threat Intelligence Enrichment
tactic: Initial Access, Command and Control
technique: T1078
sub_technique_name: null
severity: medium
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- SigninLogs
- ThreatIntelIndicators
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

# Sign-in Threat Intelligence Enrichment

## Summary
Enrichment/hunting query, not a standalone alert. Correlates sign-in
source IPs against active (non-deleted, non-expired) threat intelligence
indicators, surfacing matches ranked by TI confidence — prioritizes
sign-ins from IPs with an existing malicious reputation.

## Hypothesis
Not a behavior-anomaly hypothesis — this rule's logic is a direct join
against external threat intelligence rather than an internal baseline.
The underlying assumption is that a sign-in from an IP already flagged
by TI sources is worth prioritizing over an otherwise-unremarkable
sign-in, regardless of what Entra ID Protection's own risk engine
concludes about it independently.

## Threat intelligence context
Named per-match rather than fixed — `TI_ThreatType`, `TI_Description`,
and `TI_Sources` vary by whatever indicator the sign-in IP matches
against in the tenant's active TI feed. This is inherently a threat-
intel-driven query by design, just not tied to one specific named
family/actor/campaign at the rule level.

## Query

**Sentinel**
```kusto
let TIIndicators = ThreatIntelIndicators
| where IsDeleted == false
| where ValidUntil > now()
| summarize arg_max(TimeGenerated, *) by Id
| where ObservableKey in (
    'ipv4-addr:value',
    'ipv6-addr:value',
    'network-traffic:src_ref.value',
    'network-traffic:dst_ref.value'
  )
| extend TI_IP = ObservableValue
| extend TI_ThreatType  = tostring(Data.indicator_types[0])
| extend TI_Description = tostring(Data.description)
| summarize
    TI_ThreatType     = make_set(TI_ThreatType),
    TI_Confidence     = max(Confidence),
    TI_Description    = take_any(TI_Description),
    TI_Sources        = make_set(SourceSystem)
  by TI_IP;
SigninLogs
| join kind=inner (TIIndicators) on $left.IPAddress == $right.TI_IP
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    IsRisky,
    RiskLevelAggregated,
    RiskState,
    RiskEventTypes_V2,
    AppDisplayName,
    TI_ThreatType,
    TI_Confidence,
    TI_Description,
    TI_Sources
| sort by TI_Confidence desc, TimeGenerated desc
```
(No Defender XDR variant — `SigninLogs` and `ThreatIntelIndicators` are
Sentinel tables with no Defender XDR portal equivalent for this join.)

## What a hit looks like
A sign-in whose `IPAddress` matches an active TI indicator, sorted by
`TI_Confidence`. High-confidence matches with a specific `TI_ThreatType`
(e.g., C2, botnet) warrant immediate review regardless of what
`RiskLevelAggregated` independently reports.

## False positive notes
Shared infrastructure (cloud provider IP ranges, CDN edge nodes, VPN
exit nodes) can appear in TI feeds due to prior abuse by unrelated
parties, producing a match against a legitimate sign-in that happens to
share the same IP. Weight `TI_Confidence` and `TI_Sources` — a single
low-confidence source is weaker evidence than corroboration across
multiple feeds.

## Detection blind spots
Entirely dependent on the tenant's connected TI feeds having the
attacker's IP indexed — a sign-in from infrastructure not yet flagged by
any subscribed feed produces no match regardless of how malicious it
actually is. TI indicators also have a natural lag between
infrastructure being stood up and being reported, so this catches known-
bad infrastructure, not zero-day attacker infrastructure.

## Validation
Not applicable in the usual sense — this is a TI-correlation query, not
a behavior pattern to simulate. Validation here means confirming the
join logic works correctly: add a test indicator for a known IP to
`ThreatIntelIndicators` in a lab workspace, sign in from that IP, and
confirm the match surfaces.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/signin_threat_intel_enrichment.kql
- MITRE ATT&CK: [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) — actual technique varies by matched indicator type
