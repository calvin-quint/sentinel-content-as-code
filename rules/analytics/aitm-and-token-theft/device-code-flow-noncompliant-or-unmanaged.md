---
id: device-code-flow-noncompliant-or-unmanaged
title: "Device Code Flow \u2014 Noncompliant or Unmanaged Device"
tactic: Credential Access, Initial Access
technique: T1528, T1566
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
  id: 9237c592-6304-45da-a8a9-663f777ef9e8
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
  - T1528
  - T1566
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

# Device Code Flow — Noncompliant or Unmanaged Device

## Summary
Flags successful device-code-flow authentications where the resulting
device isn't marked compliant or isn't managed. Device code flow is the
mechanism abused in device-code phishing (the victim is lured into
entering an attacker-generated code), so any successful use from a
device Intune has never seen is a strong post-compromise indicator.

## Hypothesis
Legitimate device-code flow usage is narrow — input-constrained devices,
CLI tools, and a small set of approved automation. A successful
device-code sign-in landing on a device Intune has never registered as
compliant or managed is much more consistent with an attacker's waiting
process receiving a phished token than with normal business use.

## Threat intelligence context
Written directly as a result of **IR-2026-001** — an April 2026 account
takeover via device code phishing, originating from a ChainLink phishing
campaign using a Zoom Docs lure page. The attacker pre-generated a
device code, tricked the victim into completing the OAuth device flow,
and received a valid session token without ever obtaining credentials or
triggering an MFA prompt. This query is a near-direct match for
Detection Rule #1 written in that incident's response.

## Query

**Sentinel**
```kusto
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where ResultType == "0"
| where tobool(DeviceDetail.isCompliant) != true
      or tobool(DeviceDetail.isManaged) != true
| extend DeviceId = tostring(DeviceDetail.deviceId)
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AuthenticationProtocol, AppDisplayName, ResourceDisplayName,
          UserAgent, RiskLevelDuringSignIn, DeviceId
| order by TimeGenerated desc
```
(No Defender XDR variant — `SigninLogs` is a Sentinel/Entra ID table with
no Defender XDR portal equivalent.)

## What a hit looks like
A successful `deviceCode` sign-in where `DeviceDetail.isCompliant` and
`isManaged` are both false/absent. Cross-reference `IPAddress`/`Location`
against the user's normal pattern and check `UserAgent` for
non-standard clients (e.g. Electron-based apps) — IR-2026-001's attacker
used exactly this combination to establish persistent access.

## False positive notes
Legitimate service principals and automation (Azure CLI, approved MCP
connectors) can use device code flow from systems Intune doesn't track.
These should be enumerated and excluded explicitly by app ID rather than
by loosening the compliance/management check, which is the actual
signal here.

## Detection blind spots
Only catches sign-ins that complete successfully via device code flow —
it does nothing to prevent the flow from being initiated, and provides
no signal on the phishing delivery step itself (see
[`url_click_followed_by_device_code_authentication.md`](url_click_followed_by_device_code_authentication.md)
for that correlation). If an attacker's target device happens to already
be Intune-managed and marked compliant (e.g., a BYOD device previously
enrolled), this rule produces no signal at all.

## Validation
No public Atomic Red Team test applies — OAuth device-code-flow abuse
isn't a technique ART simulates atomically (it requires a live tenant
and an actual completed device-code exchange, not a local host action).
Validate manually: in a lab tenant, generate a device code, complete
authentication from an unmanaged test device, and confirm the rule
fires. Given this rule maps directly to a real incident, this is the
highest-priority rule in the repo to actually run through that manual
validation.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/aitm-and-token-theft/Device%20Code%20Flow%20-%20Noncompliant%20or%20Unmanaged.kql
- Incident write-up: `07-incident-response/writeups/IR-2026-001-device-code-phishing-ato.md` (calvin-quint/docs)
- MITRE ATT&CK: [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token), [T1566](https://attack.mitre.org/techniques/T1566/) (Phishing)
