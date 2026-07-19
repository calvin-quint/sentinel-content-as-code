---
id: aitm-token-replay-detection
title: AiTM Token Replay Detection
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
  id: 058afb46-37ad-4f55-9927-01f0c337a10c
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
      columnName: TokenIPs / IPs
---

# AiTM Token Replay Detection

## Summary
Detects the same session/refresh token (`UniqueTokenIdentifier`) used
across multiple IPs or countries within a 30-day window, weighted by a
composite `SignalScore` that rewards MFA-bypassed sign-ins, primary
refresh token (PRT) usage, explicit token-replay result codes, and
IPs/countries never seen for that user in a 14/90-day baseline. This is
the highest-fidelity signal for AiTM (Evilginx-style) session cookie
theft — the token itself, not just the account, is being reused from
attacker infrastructure. Current/production version; an earlier
iteration is archived in `versions/aitm-token-replay-detection/`.

## Hypothesis
The same session/refresh token being used from more than one IP or
country within 30 days is a much stronger signal than a risky sign-in
alone — tokens, unlike passwords, shouldn't move between physically
separate networks under normal use. Weighting that against MFA-bypass,
PRT usage, explicit replay result codes, and whether the IP/country is
new to the user's own baseline should rank genuine attacker replay above
coincidental multi-device use (phone + laptop on different networks,
for example).

## Threat intelligence context
No named actor, malware family, or campaign tied to this rule directly —
it's built for the general class of AiTM/session-token-replay attacks,
not one incident. Note: a related account-takeover case (IR-2026-001)
investigated a similar-looking compromise but confirmed device-code-flow
token theft rather than classic AiTM reverse-proxy replay; this rule
covers the reverse-proxy case that investigation ruled out, not the one
it confirmed.

## Query

**Sentinel**
```kusto
let ipBaseline = SigninLogs
    | where TimeGenerated > ago(14d)
    | where ResultType == "0"
    | summarize KnownIPs = make_set(IPAddress) by UserPrincipalName;
let countryBaseline = SigninLogs
    | where TimeGenerated > ago(90d)
    | where ResultType == "0"
    | summarize KnownCountries = make_set(tostring(LocationDetails.countryOrRegion))
      by UserPrincipalName;
let tokenMultiIP = SigninLogs
    | where TimeGenerated > ago(30d)
    | where isnotempty(UniqueTokenIdentifier)
    | where not(NetworkLocationDetails has "namedLocation")
    | summarize
        TokenIPs = make_set(IPAddress),
        TokenCountries = make_set(tostring(LocationDetails.countryOrRegion)),
        TokenApps = make_set(AppDisplayName),
        TokenFirstSeen = min(TimeGenerated),
        TokenLastSeen = max(TimeGenerated)
      by UniqueTokenIdentifier, UserPrincipalName
    | where array_length(TokenIPs) > 1
    | extend TokenReplayedFromMultiIP = true;
SigninLogs
| where TimeGenerated > ago(30d)
| where not(NetworkLocationDetails has "namedLocation")
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend MFABypassed = AuthenticationRequirement == "singleFactorAuthentication"
| extend TokenReplay = ResultType in ("70043", "70044")
| extend IsPRT = IncomingTokenType == "primaryRefreshToken"
| summarize
    IPs = make_set(IPAddress),
    Countries = make_set(Country),
    Apps = make_set(AppDisplayName),
    UniqueTokenIdentifiers = make_set(UniqueTokenIdentifier),
    MFABypassed = max(toint(MFABypassed)),
    TokenReplay = max(toint(TokenReplay)),
    IsPRT = max(toint(IsPRT)),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by CorrelationId, UserPrincipalName
| extend MultiIPSession = array_length(IPs) > 1
| extend MultiCountrySession = array_length(Countries) > 1
| mv-expand UniqueTokenId = UniqueTokenIdentifiers
| extend UniqueTokenIdStr = tostring(UniqueTokenId)
| join kind=inner (
    tokenMultiIP
    | project UniqueTokenIdentifier, TokenReplayedFromMultiIP, TokenIPs, TokenCountries
  ) on $left.UniqueTokenIdStr == $right.UniqueTokenIdentifier
| summarize
    IPs = any(IPs),
    Countries = any(Countries),
    Apps = any(Apps),
    UniqueTokenIdentifiers = make_set(UniqueTokenIdStr),
    TokenIPs = any(TokenIPs),
    TokenCountries = any(TokenCountries),
    MFABypassed = max(MFABypassed),
    TokenReplay = max(TokenReplay),
    IsPRT = max(IsPRT),
    MultiIPSession = max(toint(MultiIPSession)),
    MultiCountrySession = max(toint(MultiCountrySession)),
    FirstSeen = min(FirstSeen),
    LastSeen = max(LastSeen)
  by CorrelationId, UserPrincipalName
| join kind=leftouter ipBaseline on UserPrincipalName
| join kind=leftouter countryBaseline on UserPrincipalName
| extend ReplayIPIsNew = not(set_has_element(KnownIPs, tostring(TokenIPs[1])))
| extend ReplayCountryIsNew = not(set_has_element(KnownCountries, tostring(TokenCountries[1])))
| extend SignalScore = 5
    + toint(ReplayIPIsNew) * 3
    + toint(ReplayCountryIsNew) * 3
    + toint(MultiIPSession == 1 and MultiCountrySession == 1) * 2
    + toint(TokenReplay) * 2
    + toint(IsPRT) * 2
    + toint(MFABypassed) * 2
| project
    LastSeen,
    FirstSeen,
    UserPrincipalName,
    CorrelationId,
    SignalScore,
    ReplayIPIsNew,
    ReplayCountryIsNew,
    TokenIPs,
    TokenCountries,
    MultiIPSession = tobool(MultiIPSession),
    MultiCountrySession = tobool(MultiCountrySession),
    IPs,
    Countries,
    Apps,
    UniqueTokenIdentifiers,
    TokenReplay,
    IsPRT,
    MFABypassed
| order by SignalScore desc, LastSeen desc
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table with
no Defender XDR portal equivalent.)

## What a hit looks like
A high `SignalScore` with `ReplayIPIsNew` and `ReplayCountryIsNew` both
true, `TokenReplay` set, and the same `UniqueTokenIdentifier` tied to
multiple distinct IPs/countries. Prioritize by score, not just presence
of a multi-IP session.

## False positive notes
Legitimate multi-device use of the same refresh token (mobile app and
desktop client both refreshing from the same underlying session on
different networks) can produce a multi-IP session without any real
compromise. The composite `SignalScore` exists specifically to separate
that from real replay — a raw `MultiIPSession` hit alone is not
sufficient to escalate.

## Detection blind spots
The 30-day window and 14/90-day baselines mean a new employee or someone
returning from an extended trip has no reliable baseline yet, inflating
`ReplayIPIsNew`/`ReplayCountryIsNew` false positives for that population.
An attacker who never leaves the token's originating IP/country (a local
AiTM proxy in the same city as the victim) produces no multi-IP signal
at all and evades this rule entirely.

## Validation
No public Atomic Red Team test applies — cloud session-token replay
isn't a technique ART simulates atomically. Validate manually with an
Evilginx-style AiTM test harness in `offsec-lab` against a test tenant,
replaying a captured token from a second IP/geography.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/aitm-and-token-theft/AiTM%20Token%20Replay%20Detection.kql
- Earlier version archived: [`versions/aitm-token-replay-detection/`](versions/aitm-token-replay-detection/)
- MITRE ATT&CK: [T1539](https://attack.mitre.org/techniques/T1539/) (Steal Web Session Cookie), [T1550.004](https://attack.mitre.org/techniques/T1550/004/) (Use Alternate Authentication Material: Web Session Cookie)
