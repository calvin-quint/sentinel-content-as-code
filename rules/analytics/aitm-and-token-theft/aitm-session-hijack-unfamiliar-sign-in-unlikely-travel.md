---
id: aitm-session-hijack-unfamiliar-sign-in-unlikely-travel
title: "AiTM Session Hijack \u2014 Unfamiliar Sign-in + Unlikely Travel"
tactic: Credential Access, Initial Access
technique: T1539, T1078.004
sub_technique_name: Steal Web Session Cookie / Valid Accounts - Cloud Accounts
severity: high
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- SigninLogs
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
  id: af9f8abf-5b36-4f55-a050-f397a4dbe85a
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
  - CredentialAccess
  - InitialAccess
  relevantTechniques:
  - T1539
  - T1078.004
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: UnfamiliarIP / TravelIP
---

# AiTM Session Hijack — Unfamiliar Sign-in + Unlikely Travel

## Summary
Flags a user triggering both an `unfamiliarFeatures` risk event and an
`unlikelyTravel` risk event within 60 minutes of each other — the
classic pairing left behind by an adversary-in-the-middle session
hijack, where the victim signs in normally and the attacker replays the
stolen session from a geographically implausible location minutes
later.

## Hypothesis
A victim's own sign-in producing an `unfamiliarFeatures` flag, paired
tightly in time with an `unlikelyTravel` flag on the same account, is a
specific fingerprint: the real user authenticates normally (new browser
fingerprint via the phishing proxy), and the attacker replays the
captured session from a different, implausible location minutes later.
Neither event alone is unusual enough to act on; the 60-minute pairing
is the actual signal.

## Threat intelligence context
No named actor, malware family, or campaign tied to this rule directly.
Note: a related account-takeover investigation (IR-2026-001) initially
suspected classic AiTM reverse-proxy compromise, but ruled it out via
FIDO2 passkey origin-binding analysis in favor of device-code-flow token
theft instead — see
[`Device Code Flow - Noncompliant or Unmanaged.md`](Device%20Code%20Flow%20-%20Noncompliant%20or%20Unmanaged.md)
for the rule built from that incident. This rule covers the classic
reverse-proxy (Evilginx-style) case that IR-2026-001 was checked against
and excluded.

## Query

**Sentinel**
```kusto
SigninLogs
| extend RiskEvents = parse_json(RiskEventTypes)
| where RiskEvents has "unfamiliarFeatures"
| project
    UserPrincipalName,
    UnfamiliarTime = TimeGenerated,
    UnfamiliarIP = IPAddress,
    UnfamiliarCountry = tostring(LocationDetails.countryOrRegion)
| join kind=inner (
    SigninLogs
    | extend RiskEvents = parse_json(RiskEventTypes)
    | where RiskEvents has "unlikelyTravel"
    | project
        UserPrincipalName,
        TravelTime = TimeGenerated,
        TravelIP = IPAddress,
        TravelCountry = tostring(LocationDetails.countryOrRegion)
) on UserPrincipalName
| where abs(datetime_diff("minute", UnfamiliarTime, TravelTime)) <= 60
| order by UnfamiliarTime desc
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table with
no Defender XDR portal equivalent.)

## What a hit looks like
The same `UserPrincipalName` producing both risk events within the
60-minute window, with `UnfamiliarCountry` and `TravelCountry`
meaningfully different (not adjacent regions or a plausible same-day
commute).

## False positive notes
A user legitimately switching VPN/corporate proxy egress points mid-
session, or genuinely traveling with a new device, can trigger both
flags coincidentally. Check whether the two countries are geographically
close (more likely benign) versus transcontinental (more likely real) —
plausibility of travel between the two locations in the observed window
is the deciding factor.

## Detection blind spots
Entirely dependent on Entra ID Protection's built-in risk classifiers
firing in the first place — if the attacker's replay traffic doesn't
trip either `unfamiliarFeatures` or `unlikelyTravel` (e.g., replay from
an IP in the same city/country as the victim), this rule has nothing to
key off. The 60-minute join window can also miss a patient attacker who
waits hours before replaying the stolen session.

## Validation
No public Atomic Red Team test applies — cloud session-cookie theft via
a reverse proxy isn't a technique ART simulates atomically. Validate
manually with an Evilginx-style AiTM test harness in `offsec-lab` against
a test tenant, replaying a captured session from a second geography.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/aitm-and-token-theft/AiTM%20Session%20Hijack%20%E2%80%93%20Unfamiliar%20Sign-in%20%2B%20Unlikely%20Travel.kql
- MITRE ATT&CK: [T1539](https://attack.mitre.org/techniques/T1539/) (Steal Web Session Cookie), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
