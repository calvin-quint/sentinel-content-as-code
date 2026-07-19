---
id: url-click-followed-by-inbox-rule-from-new-ip
title: URL Click Followed by Inbox Rule Creation From a New IP
tactic: Initial Access, Collection
technique: T1566.002, T1114.003
sub_technique_name: Spearphishing Link / Email Forwarding Rule
severity: high
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- UrlClickEvents
- CloudAppEvents
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
  id: 19b92e2d-6b87-4dbf-a8ed-06d72fdaadc1
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
  - Collection
  relevantTechniques:
  - T1566.002
  - T1114.003
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UPN
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: ClickIPAddress / RuleIPAddress
---

# URL Click Followed by Inbox Rule Creation From a New IP

## Summary
Correlates a tracked URL click with that same user creating/modifying an
inbox rule within 60 minutes, where the rule-creation IP differs from
the click IP, is absent from a prior 14-day IP baseline, and isn't on
the `TrustedIPs` watchlist. This is the post-AiTM/post-phish persistence
step: the attacker rides the stolen session to plant a forwarding/hiding
rule from their own infrastructure, moments after the victim clicked the
lure.

## Hypothesis
A legitimate user clicking a link and then creating an inbox rule from
the same device/network shortly after is unremarkable. The same
sequence where the rule-creation IP is different from the click IP,
unseen in the user's own 14-day history, and not a known-trusted
location is much more consistent with an attacker acting through a
freshly hijacked session than with normal user behavior.

## Threat intelligence context
Thematically tied to **IR-2026-001** — the April 2026 device-code
phishing account takeover, where the attacker planted a blank-condition
archive-all inbox rule as the persistence/suppression mechanism
immediately after gaining access. This query generalizes that specific
finding into a correlation-based rule (click → rule creation from a new
IP), rather than matching the exact blank-condition rule shape alone —
narrower blank-condition matching is a separate, complementary check
elsewhere in this repo.

## Query

**Sentinel**
```kusto
UrlClickEvents
| where Timestamp > ago(90d)
| where ActionType in ("ClickAllowed", "ClickBlocked")
| project
    ClickTime = Timestamp,
    UPN = tolower(AccountUpn),
    ClickedUrl = Url,
    IsClickedThrough,
    NetworkMessageId,
    ThreatTypes,
    ClickIPAddress = IPAddress
| join kind=inner (
    CloudAppEvents
    | where Timestamp > ago(90d)
    | where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    | extend parsed = parse_json(RawEventData)
    | extend Parameters = parsed.Parameters
    | mv-expand Parameters
    | extend ParamName  = tostring(Parameters.Name)
    | extend ParamValue = tostring(Parameters.Value)
    | extend packed = pack(ParamName, ParamValue)
    | summarize
        PackedParams  = make_bag(packed),
        RuleTime      = any(Timestamp),
        RuleIPAddress = any(IPAddress),
        ActionType    = any(ActionType)
        by ReportId, UPN = tolower(tostring(parsed.UserId))
    | evaluate bag_unpack(PackedParams, OutputColumnPrefix='Rule_')
) on UPN
| where RuleTime between (ClickTime .. (ClickTime + 60m))
| where ClickIPAddress != RuleIPAddress
// 14-day IP baseline — rule IP must be new for this user
| join kind=leftanti (
    CloudAppEvents
    | where Timestamp between (ago(104d) .. ago(90d))
    | where isnotempty(IPAddress)
    | summarize KnownIPs = make_set(IPAddress) by UPN = tolower(AccountObjectId)
    | mv-expand KnownIPs
    | project UPN, RuleIPAddress = tostring(KnownIPs)
) on UPN, RuleIPAddress
// TrustedIPs watchlist check on rule IP
| join kind=leftanti (
    _GetWatchlist('TrustedIPs')
    | project RuleIPAddress = SearchKey
) on RuleIPAddress
| extend MinutesAfterClick = datetime_diff('minute', RuleTime, ClickTime)
| sort by MinutesAfterClick asc
```
(No Defender XDR variant — this query joins `UrlClickEvents` and
`CloudAppEvents` against a Sentinel watchlist, none of which have a
single-query Defender XDR portal equivalent.)

## What a hit looks like
A short `MinutesAfterClick` value with `Rule_MoveToFolder`/rule
parameters indicating archiving or forwarding, and a `RuleIPAddress`
that's new to the user and not on the trusted list. Treat low
`MinutesAfterClick` values (under ~15) as the highest-confidence tier.

## False positive notes
A user working from a new location (new office, travel, home ISP change)
who happens to click a tracked link and separately update an inbox rule
within the hour will match unless their new IP has already been added to
`TrustedIPs`. Keeping that watchlist current for legitimate remote/travel
locations is what keeps this rule's noise down — it's not optional
maintenance.

## Detection blind spots
Depends on the `TrustedIPs` watchlist being kept up to date — a stale
watchlist either produces false positives (new legitimate location) or,
if IPs are added too permissively, could suppress the real attacker
scenario if their infrastructure happens to overlap a broadly-scoped
trusted range. The 60-minute window and 90-day lookback also mean a
patient attacker who waits past the hour, or who reuses a previously-
seen IP from an earlier separate compromise, won't trigger this
specific correlation.

## Validation
No public Atomic Red Team test applies — this is a cross-table SaaS/
cloud-identity correlation, not a technique ART simulates. Validate
manually: click a tracked test lure, then create an inbox rule from a
different (new, non-trusted) IP within 60 minutes in a lab tenant, and
confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/aitm-and-token-theft/url_click_followed_by_inbox_rule_from_new_ip.kql
- Incident write-up: `07-incident-response/writeups/IR-2026-001-device-code-phishing-ato.md` (calvin-quint/docs)
- MITRE ATT&CK: [T1566.002](https://attack.mitre.org/techniques/T1566/002/) (Spearphishing Link), [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Forwarding Rule)
