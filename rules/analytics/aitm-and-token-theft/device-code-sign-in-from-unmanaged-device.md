---
id: device-code-sign-in-from-unmanaged-device
title: Device Code Sign-In From Unmanaged Device
tactic: Credential Access
technique: T1528
sub_technique_name: Steal Application Access Token
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
  id: 203f5b01-8387-407b-9943-7ccf188e0b2e
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
  relevantTechniques:
  - T1528
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

# Device Code Sign-In From Unmanaged Device

## Summary
Real-time (1-hour lookback) device-code sign-ins from an untrusted
network location where the device trust type is empty or "Unmanaged,"
enriched against a 14-day per-user IP baseline to flag whether the
source IP is new. Tighter, near-real-time sibling of the noncompliant/
unmanaged device-code rule — built for fast triage rather than
historical hunting.

## Hypothesis
Same underlying assumption as the historical-hunting sibling rule
(unmanaged/untrusted device-code auth is a strong post-compromise
indicator), narrowed to a 1-hour window and enriched with an IP-recency
check so an analyst can triage a live event in near-real time instead of
reviewing a batch of historical hits.

## Threat intelligence context
Same origin as
[`Device Code Flow - Noncompliant or Unmanaged.md`](Device%20Code%20Flow%20-%20Noncompliant%20or%20Unmanaged.md) —
written following **IR-2026-001**, an April 2026 account takeover via
device code phishing (ChainLink campaign, Zoom Docs lure). This variant
exists specifically to catch the attack while it's still unfolding,
rather than during the after-the-fact investigation that historical
hunting supports.

## Query

**Sentinel**
```kusto
let ipBaseline = SigninLogs
    | where TimeGenerated > ago(14d)
    | where ResultType == "0"
    | summarize KnownIPs = make_set(IPAddress) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| where not(NetworkLocationDetails has "namedLocation")
| where AuthenticationProtocol == "deviceCode"
| extend DeviceTrustType = tostring(DeviceDetail.trustType)
| extend DeviceCompliant = tostring(DeviceDetail.isCompliant)
| where DeviceTrustType == "" or DeviceTrustType == "Unmanaged"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| join kind=leftouter ipBaseline on UserPrincipalName
| extend NewIP = not(IPAddress in (KnownIPs))
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    NewIP,
    Location = strcat(City, ", ", Country),
    DeviceTrustType,
    DeviceCompliant,
    AppDisplayName,
    AuthenticationProtocol,
    RiskLevelDuringSignIn
| order by TimeGenerated desc
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table with
no Defender XDR portal equivalent.)

## What a hit looks like
A device-code sign-in in the last hour with `DeviceTrustType` empty or
"Unmanaged" and `NewIP` true — this combination inside a live 1-hour
window is the highest-urgency version of this detection family and
should page, not queue.

## False positive notes
Same as the historical sibling rule: legitimate service-principal/
automation use of device code flow from untracked systems will trigger
this. The 1-hour window and `NewIP` flag make it noisier for genuinely
new remote/BYOD users in their first week than the historical rule,
since there's no baseline yet to compare against.

## Detection blind spots
A 14-day-old baseline means an attacker who authenticates from an IP the
victim has (coincidentally) used before won't show as `NewIP`. Like its
sibling, this rule only fires on completed successful sign-ins — it
provides no signal on the phishing delivery step itself.

## Validation
No public Atomic Red Team test applies — see the sibling rule's
Validation section. Validate manually: generate and complete a device
code from an unmanaged test device in a lab tenant and confirm the rule
fires within the 1-hour window.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/aitm-and-token-theft/Device%20Code%20Sign-In%20From%20Unmanaged%20Device.kql
- Incident write-up: `07-incident-response/writeups/IR-2026-001-device-code-phishing-ato.md` (calvin-quint/docs)
- MITRE ATT&CK: [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token)
