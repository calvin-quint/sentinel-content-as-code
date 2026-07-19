---
id: url-click-followed-by-device-code-authentication
title: URL Click Followed by Device Code Authentication
tactic: Initial Access, Credential Access
technique: T1566.002, T1528
sub_technique_name: Spearphishing Link / Steal Application Access Token
severity: critical
confidence: high
status: production
platforms:
- sentinel
data_sources:
- UrlClickEvents
- SigninLogs
threat_intel:
  family: null
  actor: null
  campaign: "ChainLink phishing campaign \u2014 device code phishing"
  first_seen: 2026-04
  references:
  - IR-2026-001-device-code-phishing-ato.md (calvin-quint/docs, 07-incident-response/writeups/)
validated:
  atomic_test: null
  atomic_test_url: null
  lab_ref: null
  last_run: null
  result: null
owner: calvin
last_reviewed: '2026-07-19'
analytics_rule:
  id: 4b3b8c64-35eb-44a1-b5df-94e3be4fc957
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
  - InitialAccess
  - CredentialAccess
  relevantTechniques:
  - T1566.002
  - T1528
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: AccountUpn / UserPrincipalName
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: IPAddress / SigninIP
---

# URL Click Followed by Device Code Authentication

## Summary
Correlates a Safe Links-tracked URL click by a user with that same user
completing a device-code-flow sign-in within 15 minutes — the exact
sequence of a device-code phishing attack, where the clicked link leads
to a lure instructing the victim to enter an attacker-generated device
code, handing the attacker a live session token with no password or MFA
prompt of their own.

## Hypothesis
Device code phishing has a distinctive two-step shape: a link click
(the lure) immediately followed by the victim completing an actual
device-code authentication. Neither a URL click nor a device-code
sign-in is unusual in isolation — the same user doing both within a
tight 15-minute window is the specific signature of this attack, not a
generic risk heuristic.

## Threat intelligence context
This is the exact pattern documented in **IR-2026-001** — an April 2026
account takeover originating from a ChainLink phishing campaign's Zoom
Docs lure page. The victim clicked the lure, completed the OAuth device
code flow believing they were authenticating normally, and the
attacker's waiting process received the resulting token. This query was
written directly from that sequence.

## Query

**Sentinel**
```kusto
let WindowMinutes = 15;
UrlClickEvents
| where TimeGenerated > ago(20m)
| project ClickTime = TimeGenerated,
          AccountUpn, Url, NetworkMessageId, IPAddress
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(20m)
    | where AuthenticationProtocol == "deviceCode"
    | where ResultType == 0
    | project SigninTime = TimeGenerated,
              UserPrincipalName, SigninIP = IPAddress,
              AppDisplayName, UniqueTokenIdentifier,
              CorrelationId
) on $left.AccountUpn == $right.UserPrincipalName
| where SigninTime between (ClickTime .. (ClickTime + totimespan(strcat(tostring(WindowMinutes), "m"))))
| project ClickTime, SigninTime, AccountUpn,
          Url, NetworkMessageId,
          SigninIP, AppDisplayName,
          UniqueTokenIdentifier, CorrelationId
| sort by ClickTime desc
```
(No Defender XDR variant — this query joins `UrlClickEvents` and
`SigninLogs`, both Sentinel-side tables; there's no equivalent single
Defender XDR portal query for this specific cross-table correlation.)

## What a hit looks like
A `ClickTime` and `SigninTime` for the same `AccountUpn`/`UserPrincipalName`
within 15 minutes, `AuthenticationProtocol` confirmed as `deviceCode`.
This should be treated as confirmed compromise, not a candidate for
triage — IR-2026-001 showed this exact pattern preceding 25 days of
persistent attacker access.

## False positive notes
Legitimate device-code sign-ins immediately after clicking an unrelated
link (e.g., a user clicking a tracked link in one tab while separately
authenticating a CLI tool or smart-TV app in another) are theoretically
possible but rare — verify `Url` and `AppDisplayName` don't correspond to
a known, sanctioned device-code use case before treating a hit as noise.

## Detection blind spots
The 15-minute window is a judgment call based on the observed incident —
a slower attacker/victim interaction (the user hesitates before
completing the lure) could fall outside it and go undetected by this
rule specifically (though the standalone
[`Device Code Flow - Noncompliant or Unmanaged.md`](Device%20Code%20Flow%20-%20Noncompliant%20or%20Unmanaged.md)
rule would still catch the resulting sign-in on its own). Also depends
entirely on Safe Links tracking the click — a lure delivered through a
channel Safe Links doesn't cover (e.g., an external messaging platform)
produces no `UrlClickEvents` row to correlate against.

## Validation
No public Atomic Red Team test applies — OAuth device-code-flow phishing
isn't a technique ART simulates atomically. Validate manually: send a
test Safe Links-tracked lure to a lab account, click it, complete a
device-code sign-in from an unmanaged test device, and confirm the rule
fires within the 15-minute window. Given this maps directly to a real
incident, this is a high-priority candidate for that manual validation.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/aitm-and-token-theft/url_click_followed_by_device_code_authentication.kql
- Incident write-up: `07-incident-response/writeups/IR-2026-001-device-code-phishing-ato.md` (calvin-quint/docs)
- MITRE ATT&CK: [T1566.002](https://attack.mitre.org/techniques/T1566/002/) (Spearphishing Link), [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token)
