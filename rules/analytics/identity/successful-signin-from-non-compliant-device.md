---
id: successful-signin-from-non-compliant-device
title: Successful Sign-in from Non-Compliant Device
tactic: Initial Access
technique: T1078.004
sub_technique_name: Valid Accounts - Cloud Accounts
severity: medium
confidence: high
status: production
platforms:
- sentinel
data_sources:
- SigninLogs
- IdentityInfo
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
  id: 1cbf340b-493f-45cc-8ee0-746983ec4e40
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
      columnName: IPAddress
owner: calvin
last_reviewed: '2026-07-19'
---

# Successful Sign-in from Non-Compliant Device

## Summary
Real-time (1-hour) detection of successful sign-ins from non-compliant
devices, gated against a 14-day per-user IP baseline so only genuinely
new IPs surface. Enriches results with `IdentityInfo` blast-radius/tags
and a computed `RiskPriority` for triage — identity risk signals are
enrichment, not hard gates. Replaces the built-in "Successful Signin
From Non-Compliant Device" gallery rule.

## Hypothesis
A non-compliant device alone is common (BYOD, unenrolled personal
devices) and not inherently suspicious. The same sign-in from an IP the
user has never used in the last 14 days is a much stronger combined
signal — the empirical noise-reduction study behind this rule (69.6%
reduction, ~0.2 alerts/day) confirms that most non-compliant-device
sign-ins are routine and repeat from known IPs, so the new-IP gate is
what actually makes this rule usable.

## Threat intelligence context
No named actor, malware family, or campaign — a statistical/behavioral
detection, not threat-intel-driven.

## Query

**Sentinel**
```kusto
let IdentityEnrich = IdentityInfo
    | where isnotempty(AccountUpn)
    | summarize arg_max(TimeGenerated, *) by AccountUpn
    | project
        AccountUpn = tolower(AccountUpn),
        BlastRadius,
        Tags;
let Baseline = SigninLogs
    | where TimeGenerated between (ago(15d) .. ago(1h))
    | where ResultType == 0
    | where tostring(DeviceDetail.isCompliant) == "false"
    | summarize KnownIPs = make_set(IPAddress) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| where tostring(DeviceDetail.isCompliant) == "false"
| extend UPNLower = tolower(UserPrincipalName)
| join kind=leftouter Baseline on UserPrincipalName
| where not(set_has_element(KnownIPs, IPAddress))
| join kind=leftouter IdentityEnrich on $left.UPNLower == $right.AccountUpn
| extend
    IsHighBlastRadius = BlastRadius == "High",
    IsMedBlastRadius  = BlastRadius == "Medium",
    HasEntraRisk      = RiskLevelDuringSignIn != "none"
        and isnotempty(RiskLevelDuringSignIn),
    HasCANonSuccess   = ConditionalAccessStatus != "success"
        and isnotempty(ConditionalAccessStatus)
| extend
    RiskPriority = case(
        HasEntraRisk,                        3,
        IsHighBlastRadius,                   2,
        HasCANonSuccess or IsMedBlastRadius, 1,
        0
    )
| extend
    DeviceId        = tostring(DeviceDetail.deviceId),
    DeviceName      = tostring(DeviceDetail.displayName),
    OperatingSystem = tostring(DeviceDetail.operatingSystem),
    TrustType       = tostring(DeviceDetail.trustType),
    City            = tostring(LocationDetails.city),
    Country         = tostring(LocationDetails.countryOrRegion)
| project
    TimeGenerated,
    UserPrincipalName,
    UserDisplayName,
    IPAddress,
    City,
    Country,
    AppDisplayName,
    ResourceDisplayName,
    DeviceId,
    DeviceName,
    OperatingSystem,
    TrustType,
    BlastRadius,
    RiskPriority,
    IsHighBlastRadius,
    HasEntraRisk,
    HasCANonSuccess,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskDetail,
    AuthenticationRequirement,
    IsInteractive,
    Tags
| extend
    Account_0_Name      = tostring(split(UserPrincipalName, "@")[0]),
    Account_0_UPNSuffix = tostring(split(UserPrincipalName, "@")[1]),
    IP_0_Address        = IPAddress
| sort by RiskPriority desc, TimeGenerated desc
```
(No Defender XDR variant — `SigninLogs` and `IdentityInfo` are Sentinel/
Entra ID tables with no Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `PT1H` |
| Suppression | `PT24H` |
| Grouping | By account, 24h window |
| Entity mappings | `Account.Name = Account_0_Name` · `Account.UPNSuffix = Account_0_UPNSuffix` · `IP.Address = IP_0_Address` |
| Custom details | `RiskPriority`, `BlastRadius`, `HasEntraRisk`, `HasCANonSuccess`, `DeviceName`, `TrustType` |
| Replaces | Successful Signin From Non-Compliant Device (gallery) |

## What a hit looks like
`RiskPriority == 3` (an actual Entra risk signal present) is the top
tier, followed by high blast radius, then CA non-success or medium
blast radius. `RiskPriority == 0` hits are lower urgency — new IP on a
non-compliant device with no other corroborating signal.

## False positive notes
New remote-work locations, travel, or ISP changes on already-non-
compliant BYOD devices will still generate `RiskPriority == 0`/low-
priority hits after the IP baseline gate — the baseline reduces volume
but doesn't eliminate legitimate new-IP events entirely. Use
`RiskPriority` to triage rather than treating every hit as equally
urgent.

## Detection blind spots
The 14-day IP baseline means a new employee or someone who's changed
location frequently in the last two weeks has an unreliable baseline in
either direction. An attacker signing in from an IP the legitimate user
has coincidentally used before (e.g., a shared/NAT'd corporate egress)
won't show as a new IP and evades the baseline gate entirely.

## Validation
Not yet tested against a simulated attack. Validation to date is
empirical/production-based: the 69.6% noise reduction and ~0.2 alerts/
day figures come from live tenant tuning, not an attack-simulation run.
Next step: sign in from a non-compliant device using an IP outside the
account's 14-day baseline in a lab tenant and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity/successful_signin_from_non_compliant_device.kql
- Replaces built-in Sentinel gallery rule: "Successful Signin From Non-Compliant Device"
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
