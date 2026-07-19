---
id: token-theft-and-replay-detection
title: Token Theft and Replay Detection
tactic: Credential Access, Defense Evasion, Persistence
technique: T1539, T1550.004
sub_technique_name: Steal Web Session Cookie / Use Alternate Authentication Material
  - Web Session Cookie
severity: high
confidence: high
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
  id: 9aa10d60-2f52-494c-a1e3-b989e57f186e
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
  - DefenseEvasion
  - Persistence
  relevantTechniques:
  - T1539
  - T1550.004
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: IPAddress
---

# Token Theft and Replay Detection

## Summary
Detects high-risk sign-ins where the MFA requirement was satisfied by a
previously-issued token claim (not a fresh MFA prompt), self-joined
against the same user's immediately prior sign-in to compute impossible
country/state/city travel between the two. Broadens the trigger from a
strict AND to an OR across three paths (claim-satisfied, previously-
satisfied, or approved mobile push) to catch variants earlier archived
versions missed. Current/production version; v1-v3 archived in
`versions/token-theft-and-replay-detection/`.

## Hypothesis
A high-risk sign-in where MFA was satisfied by a stale token claim
rather than a fresh challenge, immediately followed by a sign-in from an
impossible location relative to the prior one, is a stronger signal than
either impossible travel or a stale-claim sign-in alone — the pairing is
what a stolen, replayed session actually looks like end to end, not just
a single suspicious event.

## Threat intelligence context
No named actor, malware family, or campaign — built for the general
class of token-theft-and-replay attacks. Related but distinct from
**IR-2026-001** (device-code phishing account takeover): that
investigation's key takeaway was that detection should focus on
`AuthenticationProtocol == "deviceCode"` combined with device/location
signals, not on MFA-claim behavior — this rule covers the complementary
angle (stale MFA claim + impossible travel) rather than the device-code
vector that incident confirmed.

## Query

**Sentinel**
```kusto
SigninLogs
| where ResultType in (0, 50125, 50140, 70043, 70044)
  and Status.errorCode == 0
  and RiskLevelDuringSignIn == "high"
  and (IncomingTokenType == "none" or isnull(IncomingTokenType))
  and ConditionalAccessStatus == "success"
  and (
        AuthenticationDetails has "MFA requirement satisfied by claim in the token"
     or AuthenticationDetails has "Previously satisfied"
     or (AuthenticationDetails has "Mobile app notification" and AuthenticationDetails has '"succeeded":true')
  )
| extend
    Country = tostring(LocationDetails["countryOrRegion"]),
    State = tostring(LocationDetails["state"]),
    City = tostring(LocationDetails["city"]),
    AuthRequirement = tostring(parse_json(AuthenticationDetails)[0].authenticationStepRequirement),
    AuthMethod = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod),
    AuthDetail = tostring(parse_json(AuthenticationDetails)[0].authenticationStepResultDetail),
    SignInOutcome = case(
        ResultType == 0, "Success",
        ResultType in (50125, 50140), "Partial MFA",
        ResultType == 70044, "Token Replay",
        ResultType == 70043, "Expired/Invalid Token",
        "Other"
    )
| join kind=inner (
    SigninLogs
    | where ResultType in (0, 50125, 50140, 70043, 70044)
      and Status.errorCode == 0
      and RiskLevelDuringSignIn == "high"
      and (IncomingTokenType == "none" or isnull(IncomingTokenType))
      and ConditionalAccessStatus == "success"
      and (
            AuthenticationDetails has "MFA requirement satisfied by claim in the token"
         or AuthenticationDetails has "Previously satisfied"
         or (AuthenticationDetails has "Mobile app notification" and AuthenticationDetails has '"succeeded":true')
      )
    | extend
        PreviousTime = TimeGenerated,
        PreviousCountry = tostring(LocationDetails["countryOrRegion"]),
        PreviousState = tostring(LocationDetails["state"]),
        PreviousCity = tostring(LocationDetails["city"])
    | project UserPrincipalName, PreviousTime, PreviousCountry, PreviousState, PreviousCity
) on UserPrincipalName
| where PreviousTime < TimeGenerated
| summarize arg_min(TimeGenerated, *) by UserPrincipalName, TimeGenerated
| extend
    ImpossibleCountryTravel = iff(Country != PreviousCountry and isnotempty(PreviousCountry), true, false),
    ImpossibleStateTravel   = iff(State   != PreviousState   and isnotempty(PreviousState), true, false),
    ImpossibleCityTravel    = iff(City    != PreviousCity    and isnotempty(PreviousCity), true, false)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country,
    State,
    City,
    PreviousCountry,
    PreviousState,
    PreviousCity,
    ImpossibleCountryTravel,
    ImpossibleStateTravel,
    ImpossibleCityTravel,
    ResultType,
    SignInOutcome,
    AppDisplayName,
    ResourceDisplayName,
    RiskLevelDuringSignIn,
    IncomingTokenType,
    AuthRequirement,
    AuthMethod,
    AuthDetail,
    ClientAppUsed,
    DeviceDetail,
    CorrelationId,
    OriginalRequestId
| order by TimeGenerated desc
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table with
no Defender XDR portal equivalent.)

## What a hit looks like
A high-risk sign-in with a stale MFA claim (`AuthMethod`/`AuthDetail`
showing "Previously satisfied" or claim-based, not a fresh prompt) where
`ImpossibleCountryTravel` (or state/city) is true relative to the same
user's immediately prior sign-in. `SignInOutcome` of "Token Replay"
(`ResultType == 70044`) is the highest-confidence variant.

## False positive notes
Users on corporate VPNs that egress from different regions between
sessions, or mobile users switching between cellular and Wi-Fi networks
that resolve to different geo-IP locations, can produce impossible-
travel pairings without any real token theft. Check `ClientAppUsed` and
`DeviceDetail` consistency between the two sign-ins — a real replay
typically shows a different device/client than the legitimate one.

## Detection blind spots
Only compares against the immediately prior sign-in (`arg_min` by
`UserPrincipalName, TimeGenerated`) — it has no broader baseline, so a
user with genuinely erratic travel patterns will generate recurring
false positives, and an attacker who replays from the same country/state
as the victim's last sign-in produces no impossible-travel signal at
all. `RiskLevelDuringSignIn == "high"` is a hard gate — if Entra ID
Protection doesn't classify the sign-in as high risk, this rule never
sees it regardless of how suspicious the underlying token behavior is.

## Validation
No public Atomic Red Team test applies — cloud session-token replay
isn't a technique ART simulates atomically. Validate manually with an
Evilginx-style AiTM test harness in `offsec-lab`, replaying a captured
token from a geographically distant IP relative to the victim's last
sign-in.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/aitm-and-token-theft/Token%20Theft%20and%20Replay%20Detection.kql
- Earlier versions archived: [`versions/token-theft-and-replay-detection/`](versions/token-theft-and-replay-detection/)
- Related incident (different attack vector, ruled-out AiTM): `07-incident-response/writeups/IR-2026-001-device-code-phishing-ato.md` (calvin-quint/docs)
- MITRE ATT&CK: [T1539](https://attack.mitre.org/techniques/T1539/) (Steal Web Session Cookie), [T1550.004](https://attack.mitre.org/techniques/T1550/004/) (Use Alternate Authentication Material: Web Session Cookie)
