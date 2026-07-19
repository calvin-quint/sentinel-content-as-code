---
id: anomalous-signin-activity
title: UEBA Anomalous Sign-in Activity
tactic: Initial Access
technique: T1078.004
sub_technique_name: Valid Accounts - Cloud Accounts
severity: medium
confidence: high
status: production
platforms:
- sentinel
data_sources:
- BehaviorAnalytics
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
analytics_rule:
  id: 2a187a69-fbd9-4064-838b-0c285e04ebb8
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
  relevantTechniques:
  - T1078.004
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: Name
      columnName: Account_0_Name
    - identifier: UPNSuffix
      columnName: Account_0_UPNSuffix
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: SourceIPAddress
owner: calvin
last_reviewed: '2026-07-19'
---

# UEBA Anomalous Sign-in Activity

## Summary
Joins `BehaviorAnalytics` sign-in anomaly signals (dormant account,
first-time country/ISP, uncommon country/ISP) against `SigninLogs` risk
and Conditional Access context, then gates on a hard final condition —
`InvestigationPriority >= 5`, a non-none sign-in risk level, or a
dormant-account flag — so raw anomaly-flag noise alone can't trigger the
rule. Replaces the built-in "Anomalous sign-in activity" Content Hub
gallery rule.

## Hypothesis
Country/ISP anomaly flags alone are too common to act on directly — the
empirical tuning behind this rule (see False positive notes) showed
thousands of events per day at lower priority thresholds, nearly all
recurring/benign churn. Requiring at least one hard corroborating
signal (high investigation priority, actual sign-in risk, or a dormant
account suddenly active) turns a noisy behavioral flag into a much
smaller, higher-confidence set worth an analyst's time.

## Threat intelligence context
No named actor, malware family, or campaign — this is a statistical/
UEBA-driven detection, not threat-intel-driven.

## Query

**Sentinel**
```kusto
BehaviorAnalytics
| where TimeGenerated > ago(90d)
| where ActionType =~ "Sign-in"
| where
    UsersInsights.IsDormantAccount == true
    or ActivityInsights.FirstTimeUserConnectedFromCountry == true
    or ActivityInsights.CountryUncommonlyConnectedFromByUser == true
    or ActivityInsights.FirstTimeUserConnectedViaISP == true
    or ActivityInsights.ISPUncommonlyUsedByUser == true
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(90d)
    | where toint(Status.errorCode) == 0
    | project
        _ItemId,
        SignInRiskDetail    = tostring(RiskDetail),
        SignInRiskLevel     = tostring(RiskLevelDuringSignIn),
        ConditionalAccess   = tostring(ConditionalAccessStatus),
        AppDisplayName,
        ResourceDisplayName,
        ResourceId
) on $left.SourceRecordId == $right._ItemId
// Final gate — must meet at least one of these three hard conditions
// ActivityInsights country/ISP signals alone are insufficient without priority
| where InvestigationPriority >= 5
    or SignInRiskLevel != "none"
    or tobool(UsersInsights.IsDormantAccount) == true
| extend
    BlastRadius      = tostring(UsersInsights.BlastRadius),
    IsNewAccount     = tobool(UsersInsights.IsNewAccount),
    IsDormantAccount = tobool(UsersInsights.IsDormantAccount),
    IsLocalAdmin     = tobool(UsersInsights.IsLocalAdmin)
| extend
    UserPrincipalName = iff(
        UserPrincipalName has "#EXT#",
        replace_string(tostring(split(UserPrincipalName, "#")[0]), "_", "@"),
        UserPrincipalName
    ),
    UserName = iff(
        UserName has "#EXT#",
        replace_string(tostring(split(UserName, "#")[0]), "_", "@"),
        UserName
    )
| project
    TimeGenerated,
    UserName,
    UserPrincipalName,
    InvestigationPriority,
    BlastRadius,
    IsNewAccount,
    IsDormantAccount,
    IsLocalAdmin,
    ActivityType,
    ActionType,
    Evidence            = ActivityInsights,
    UsersInsights,
    AppDisplayName,
    ResourceDisplayName,
    SignInRiskDetail,
    SignInRiskLevel,
    ConditionalAccess,
    SourceIPAddress,
    SourceIPLocation,
    SourceDevice,
    DevicesInsights,
    ResourceId
| extend
    Account_0_Name             = tostring(split(UserPrincipalName, "@")[0]),
    Account_0_UPNSuffix        = tostring(split(UserPrincipalName, "@")[1]),
    IP_0_Address               = SourceIPAddress,
    AzureResource_0_ResourceId = ResourceId
| sort by InvestigationPriority desc, TimeGenerated desc
```
(No Defender XDR variant — `BehaviorAnalytics` is a Sentinel UEBA table
with no Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `PT1H` |
| Suppression | `PT24H` |
| Grouping | By account, 24h window |
| Entity mappings | `Account.Name = Account_0_Name` · `Account.UPNSuffix = Account_0_UPNSuffix` · `IP.Address = IP_0_Address` · `AzureResource.ResourceId = AzureResource_0_ResourceId` |
| Custom details | `InvestigationPriority`, `BlastRadius`, `IsNewAccount`, `IsDormantAccount`, `IsLocalAdmin`, `SignInRiskLevel`, `SignInRiskDetail` |
| Replaces | Anomalous sign-in activity (Content Hub gallery) |

## What a hit looks like
High `InvestigationPriority` combined with a non-"none" `SignInRiskLevel`
and a populated `BlastRadius` is the top tier. A `IsDormantAccount`
account suddenly signing in is worth immediate attention regardless of
`InvestigationPriority`.

## False positive notes
Directly tuned against 90 days of live tenant data before shipping:
requiring `InvestigationPriority >= 5` narrowed matches to 9 events
across 3 users, versus 15,773 events across 61 users at `>= 4` (excluded
as recurring churn) and 3,865 events across 104 users at `>= 3` (excluded
as normal behavior). The threshold is a deliberate, data-backed cliff,
not an arbitrary round number — don't lower it without re-running that
same kind of baseline check.

## Detection blind spots
Entirely dependent on `BehaviorAnalytics`' own anomaly flags and
`InvestigationPriority` scoring — this rule adds a gating/correlation
layer on top but no independent detection logic. New or low-activity
accounts have unreliable baselines, same as the other UEBA-based rules
in this repo. The `#EXT#` UPN-normalization logic assumes a specific
guest-account naming convention (`name_domain.com#EXT#...`) — a
differently formatted external identity could fail to normalize
correctly.

## Validation
Not yet tested against a simulated attack. Validation to date is
empirical/production-based (the 90-day threshold study above), which is
a different kind of evidence than an attack-simulation run. Next step:
simulate a dormant-account sign-in or new-country/ISP sign-in with
elevated investigation priority in a lab tenant and confirm the rule
fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/ueba/anomalous_signin_activity.kql
- Replaces built-in Sentinel gallery rule: "Anomalous sign-in activity" (Content Hub)
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
