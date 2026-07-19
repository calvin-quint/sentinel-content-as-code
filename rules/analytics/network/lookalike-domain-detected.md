---
id: lookalike-domain-detected
title: Lookalike / Typosquat Domain Detected
tactic: Resource Development
technique: T1583.001, T1584.001
sub_technique_name: Acquire/Compromise Infrastructure - Domains
severity: high
confidence: medium
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
  id: 28c1fde4-e98b-4fc3-9b33-c02581d31b84
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

# Lookalike / Typosquat Domain Detected

## Summary
Flags domains queried by the environment that closely resemble a
maintained watchlist of brand/vendor domains — classic typosquat/
lookalike patterns: character insertion, hyphenation, or a numeric
suffix/prefix around the brand name. Requires a `BrandDomains`
watchlist (one column, `DomainName`) seeded with the legitimate
corporate/vendor domains to protect. Companion rule to
[`newly-registered-domain-first-seen.md`](newly-registered-domain-first-seen.md).

## Hypothesis
A queried domain whose label contains, or is a hyphen/numeric variant
of, a protected brand's root name — but isn't the real domain itself —
is consistent with someone in the environment having clicked a
typosquat/lookalike link. KQL has no native edit-distance function, so
this uses substring containment plus hyphen/suffix regex patterns
instead of true Levenshtein distance; good enough to catch the common
cases without a plugin, at the cost of missing subtler homoglyph or
transposition-style typosquats.

## Threat intelligence context
No named actor, malware family, or campaign tied to this rule directly
— it's a generic brand-protection detection driven by whatever domains
are seeded into the `BrandDomains` watchlist. This is the closest
existing rule to a dedicated AiTM/phishing-infrastructure early-warning
capability in this repo — it detects *internal* contact with lookalike
infrastructure, complementary to an external Certificate Transparency
watcher that would catch the same infrastructure being registered in
the first place, before anyone inside the org queries it.

## Query

**Sentinel**
```kusto
let brandRoots = toscalar(
    _GetWatchlist("BrandDomains")
    | project BrandRoot = tostring(split(DomainName, ".")[0])
    | summarize make_list(BrandRoot)
);
_Im_Dns(starttime = ago(1d), endtime = now())
| where isnotempty(DnsQuery)
| extend QueryRoot = tolower(DnsQuery)
| extend QueryLabel = tostring(split(QueryRoot, ".")[0])
| mv-apply BrandRoot = brandRoots to typeof(string) on (
    where QueryLabel has BrandRoot
       or QueryLabel matches regex strcat(BrandRoot, @"[-0-9]{1,4}$")   // brand + hyphen/number suffix
       or QueryLabel matches regex strcat(@"^[-0-9]{1,4}", BrandRoot)  // hyphen/number prefix + brand
)
| where QueryRoot !endswith strcat(BrandRoot, ".com")          // drop legit exact matches of the real brand
    and QueryLabel != BrandRoot                                // drop exact label matches (real domain)
| summarize FirstSeen = min(TimeGenerated), QueryCount = count(), Devices = make_set(SrcIpAddr, 10)
    by DnsQuery, BrandRoot
| order by FirstSeen desc
```
(No Defender XDR variant — this uses the ASIM DNS normalization parser
`_Im_Dns` plus a Sentinel watchlist lookup, neither of which has a
Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Resource Development — T1583.001, T1584.001 |
| Entity mappings | `DNS.DomainName = DnsQuery` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DnsQuery` matching a `BrandRoot` via substring or hyphen/number
suffix/prefix, that isn't the real `.com` domain itself. Check `Devices`
for how many hosts contacted it and whether any of them subsequently
completed an authentication flow (correlate against sign-in logs for
those devices/users).

## False positive notes
Internal subdomains or CDN/marketing subdomains of the *actual*
protected brand can self-match if the watchlist's `BrandDomains` isn't
scoped to just the root domain — exclude the real root domains
explicitly from the comparison set (already partially handled by the
`!endswith` and label-equality checks, but verify against your actual
subdomain structure). Query volume alone isn't scored — a lookalike hit
happening frequently isn't automatically more or less suspicious than
one happening once.

## Detection blind spots
Substring/regex matching catches insertion, hyphenation, and
numeric-affix typosquats but misses homoglyph attacks (visually similar
Unicode characters), transposition (swapped letters), and
combosquatting with unrelated words (`brand-support-portal.tld` where
"support-portal" isn't a hyphen/number pattern) — a proper Levenshtein/
edit-distance engine (e.g., dnstwist-generated permutations checked
against this same DNS stream) would close this gap. Also entirely
dependent on the `BrandDomains` watchlist being kept current — a brand
or newly acquired subsidiary not yet added produces no protection at
all.

## Validation
No confirmed Atomic Red Team test identified — typosquat DNS detection
isn't a technique ART simulates (it requires querying an actual
registered lookalike domain, not a local host action). Validate
manually: seed the `BrandDomains` watchlist with a test brand, query a
hyphenated/numeric variant of it from a lab device, and confirm the
rule fires.

## References
- MITRE ATT&CK: [T1583.001](https://attack.mitre.org/techniques/T1583/001/) / [T1584.001](https://attack.mitre.org/techniques/T1584/001/) (Acquire/Compromise Infrastructure: Domains)
