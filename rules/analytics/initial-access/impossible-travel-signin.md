---
id: impossible-travel-signin
title: Impossible Travel Sign-in for a Single User
tactic: Initial Access
technique: T1078
sub_technique_name: Valid Accounts
severity: medium
confidence: medium
status: production
platforms: [sentinel]
data_sources: [SigninLogs]
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
  id: 8f0b1e2a-6c3d-4a1f-9b2e-1a2b3c4d5e6f
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: PT2H
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  requiredDataConnectors:
    - connectorId: AzureActiveDirectory
      dataTypes: [SigninLogs]
  tactics: [InitialAccess]
  relevantTechniques: [T1078]
  entityMappings:
    - entityType: Account
      fieldMappings:
        - identifier: FullName
          columnName: UserPrincipalName
    - entityType: IP
      fieldMappings:
        - identifier: Address
          columnName: IPAddress
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

# Impossible Travel Sign-in for a Single User

## Summary
Detects a successful Azure AD sign-in from a user occurring from two
geographically distant locations within a time window that is not
physically feasible, indicating possible credential compromise.

## Hypothesis
A single account signing in successfully from two locations more than
800km apart within under an hour of each other cannot represent one
person traveling — either the account is being used from two places at
once (a shared/leaked credential) or a session is being replayed from
attacker infrastructure. Computing this directly from geo-coordinates
and elapsed time is a straightforward physical-plausibility check, not
a statistical anomaly model.

## Threat intelligence context
No named actor, malware family, or campaign — a generic geo-velocity
detection applicable to any account-compromise scenario.

## Query

**Sentinel**
```kusto
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location = tostring(LocationDetails.city), Latitude = todouble(LocationDetails.geoCoordinates.latitude), Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevLat = prev(Latitude), PrevLon = prev(Longitude), PrevUser = prev(UserPrincipalName), PrevLocation = prev(Location)
| where UserPrincipalName == PrevUser
| extend TimeDeltaHours = datetime_diff('minute', TimeGenerated, PrevTime) / 60.0
| extend DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000
| where TimeDeltaHours > 0 and TimeDeltaHours < 1 and DistanceKm > 800
| project TimeGenerated, UserPrincipalName, IPAddress, Location, PrevLocation, TimeDeltaHours, DistanceKm
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `PT2H` |
| Trigger | `gt 0` |
| Tactics / Techniques | Initial Access — T1078 |
| Entity mappings | `Account.FullName = UserPrincipalName` · `IP.Address = IPAddress` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `UserPrincipalName` with `DistanceKm > 800` and `TimeDeltaHours < 1`
between two consecutive successful sign-ins. Check `IPAddress` and
`Location`/`PrevLocation` for VPN/corporate-proxy explanations before
escalating.

## False positive notes
Corporate VPNs and cloud-based proxy services that route traffic
through distant egress points are the primary source of noise here — a
user connecting through a VPN exit node in a different country than
their previous sign-in can trip this without any real compromise.
Maintain awareness of the org's VPN egress locations when triaging.

## Detection blind spots
This query relies on `serialize` + `prev()` ordered strictly by
`UserPrincipalName, TimeGenerated` — it only ever compares a sign-in to
the *immediately preceding* one for that user, so it has no broader
baseline and can't detect travel that's impossible relative to a
sign-in from, say, three events back. An attacker signing in from a
location that happens to be *within* 800km of the victim's last known
location (or waiting more than an hour before reusing a session)
produces no signal at all.

## Validation
No confirmed Atomic Red Team test identified — impossible-travel
geo-velocity is a cloud-identity analytics pattern, not a technique ART
simulates directly (it requires two real, geographically distant
sign-ins, not a local host action). Validate manually: sign in as a
test account from two different geographies (e.g., via VPN) within an
hour and confirm the rule fires.

## References
- MITRE ATT&CK: [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts)
