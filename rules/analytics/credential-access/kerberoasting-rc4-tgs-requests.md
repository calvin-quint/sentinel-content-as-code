---
id: kerberoasting-rc4-tgs-requests
title: Kerberoasting - Anomalous RC4-Encrypted TGS Request Volume
tactic: Credential Access
technique: T1558.003
sub_technique_name: Steal or Forge Kerberos Tickets - Kerberoasting
severity: high
confidence: medium
status: production
platforms: [sentinel]
data_sources: [SecurityEvent]
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
  id: e6642412-4a1a-43cf-bf77-3c423d116ce9
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [CredentialAccess]
  relevantTechniques: [T1558.003]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: Computer
    - entityType: IP
      fieldMappings:
        - identifier: Address
          columnName: IpAddress
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
last_reviewed: "2026-07-29"
---

# Kerberoasting - Anomalous RC4-Encrypted TGS Request Volume

## Summary
Detects a burst of Kerberos service-ticket (TGS) requests encrypted
with RC4 (`0x17`) from a single source in a short window — the
signature of an offline Kerberoasting run, where a tool like Rubeus or
Impacket's `GetUserSPNs.py` requests service tickets for every SPN it
can enumerate in order to crack them offline.

## Hypothesis
A legitimate service ticket request happens once per service per user
session, roughly matching normal login/access patterns, and modern
domain-joined clients default to AES for ticket encryption. RC4 tickets
still occur legitimately (older clients, RC4-only service accounts,
some legacy applications), but a single account or host requesting
more than a handful of RC4-encrypted TGS tickets in a short window is a
materially different pattern — that volume only makes sense as an
enumeration sweep against every SPN in the domain, not normal
day-to-day resource access.

## Threat intelligence context
Sourced from CyberProof's H1 2026 case study on the same
Teams-vishing/Quick-Assist attack family this repo's own IR-2026-004
incident belongs to — that case study confirmed Kerberoasting as a
follow-on technique in a comparable intrusion after initial access via
the same social-engineering vector. Not yet independently confirmed
against this environment for IR-2026-004 itself; treat detections here
as a genuine unknown rather than an expected finding until validated.

## Query

**Sentinel**
```kusto
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4 - legitimate services should use AES
| where ServiceName !endswith "$"       // exclude machine account service tickets
| summarize RequestCount = count(), Accounts = make_set(TargetUserName) by Computer, IpAddress
| where RequestCount > 5                // tune threshold against this environment's normal RC4 baseline
| order by RequestCount desc
```
(No Defender XDR variant — `SecurityEvent` Event ID 4769 requires the
Windows Security Events connector (AMA/legacy agent) with "Audit
Kerberos Service Ticket Operations" enabled on the DCs; this event is
not available via Defender XDR advanced hunting tables.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Credential Access — T1558.003 |
| Entity mappings | `Host.Name = Computer` · `IP.Address = IpAddress` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
`RequestCount > 5` RC4-encrypted TGS requests from a single
`Computer`/`IpAddress` in the query window, with `Accounts` showing a
spread of distinct `TargetUserName` values rather than one account
repeatedly accessing the same service — that spread is what
distinguishes an enumeration sweep from a single busy legitimate
service account. Cross-reference the source host against known
scanning/vulnerability-assessment infrastructure before escalating.

## False positive notes
Legacy applications and RC4-only service accounts (older SQL Server
instances, some line-of-business apps that haven't been migrated to
AES) are the expected source of noise, and will show up as a
consistent, narrow `Accounts` set (typically the same one or two
service accounts) rather than a broad sweep. Baseline RC4 request
volume per host for a few days before tuning `RequestCount` down from
the starting threshold of 5, and maintain a `KnownRC4Services`
allowlist for confirmed-legitimate legacy accounts.

## Detection blind spots
Requires "Audit Kerberos Service Ticket Operations" enabled on the DCs
and the Windows Security Events connector ingesting Event ID 4769 — an
empty result without that confirmed enabled is unmeasured, not clean,
the same trap as other `SecurityEvent`-dependent rules in this repo. A
Kerberoasting run that requests AES-encrypted tickets instead of RC4
(less crackable, but used by more OPSEC-aware tooling/actors) produces
no signal here at all — this rule only catches the RC4 variant of the
technique. A low-and-slow roast (a handful of tickets per hour, staying
under the volume threshold) also evades detection.

## Validation
No confirmed Atomic Red Team test identified for this exact query
against a live tenant; this rule has never been run against real OMNIA
data as of this writing (see the source incident's own checklist —
Section 6 "queries still never run"). Validate manually: run
`GetUserSPNs.py` or Rubeus `kerberoast` against a lab domain with
several SPN-registered accounts and confirm both the RC4 filter and
the volume threshold fire correctly before relying on this in
production.

## References
- MITRE ATT&CK: [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting)
- Source case study: CyberProof H1 2026 report on Teams-vishing/Quick-Assist-driven intrusions
