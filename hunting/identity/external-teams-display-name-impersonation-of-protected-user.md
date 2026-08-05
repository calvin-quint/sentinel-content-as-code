---
id: "external-teams-display-name-impersonation-of-protected-user"
title: "External Teams Display Name Impersonation of Protected User"
tactic: "Defense Evasion"
technique: "T1036.005"
sub_technique_name: "Match Legitimate Resource Name or Location"
severity: "high"
confidence: "medium"
status: draft
platforms: [defender_xdr]
data_sources: [CloudAppEvents, IdentityInfo]
sigma_source: null
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references: []
  yara_rule: null
validated:
  atomic_test: null
  atomic_test_url: null
  lab_ref: null
  last_run: null
  result: null
owner: "Calvin Quint"
last_reviewed: "2026-08-05"
---

# External Teams Display Name Impersonation of Protected User

## Summary
Detects an external Microsoft Teams call or meeting participant whose displayed name matches the normalized name of a member of a configured protected-user group while the participant signs in with a different external identity. This can reveal social-engineering attempts that impersonate support or infrastructure personnel during Teams interactions.

## Hypothesis
External participants should not present the same display name as internal personnel in protected administrative or support roles. An external identity using such a name is more likely to be impersonating a trusted employee to influence users or gain access.

## Threat intelligence context
This is a behavior-based impersonation hunt with no specific malware, actor, or campaign attribution. Adversaries can abuse collaboration-platform display names to masquerade as trusted personnel, particularly staff whose roles commonly involve access requests, troubleshooting, or urgent technical instructions.

## Query

**Defender XDR**
```kusto
// ===== SET THESE VALUES =====
// Replace both placeholders with the exact Entra ID group display names whose members
// should be protected from external Teams display-name impersonation.
let _Lookback = 30d;
let _ProtectedGroupNames = dynamic([
    "REPLACE_WITH_INFRASTRUCTURE_GROUP_NAME",
    "REPLACE_WITH_SERVICE_DESK_GROUP_NAME"
]);
// ============================
let ProtectedUsers =
    IdentityInfo
    | summarize arg_max(TimeGenerated, *) by AccountUpn
    | where GroupMembership has_any (_ProtectedGroupNames)
    | extend NormalizedDisplayName = replace_string(AccountName, ".", " ")
    | project AccountUpn, NormalizedDisplayName;
CloudAppEvents
| where Timestamp > ago(_Lookback)
| where Application == "Microsoft Teams"
| where ActionType in ("CallParticipantDetail", "MeetingParticipantDetail")
| where IsExternalUser
| mv-expand Attendee = RawEventData.Attendees
| extend
    AttendeeUPN = tostring(Attendee.UPN),
    AttendeeDisplayName = tostring(Attendee.DisplayName)
| where AttendeeUPN == AccountId
| join kind=inner (ProtectedUsers | project NormalizedDisplayName, SpoofedRealAccount = AccountUpn)
    on $left.AttendeeDisplayName == $right.NormalizedDisplayName
| project Timestamp, CallId = tostring(RawEventData.CallId), SpoofDisplayName = AttendeeDisplayName, SpoofUPN = AccountId, SpoofedRealAccount, IPAddress, City, ISP
| order by Timestamp desc
```

## What a hit looks like
A result identifies the meeting or call, external UPN, impersonated display name, corresponding protected internal account, source IP address, city, and ISP. Analysts should verify whether the real employee participated, inspect the meeting organizer and other attendees, and review messages or requests made by the external participant.

## False positive notes
Two people can legitimately share the same display name, and guests may represent partner personnel with names matching internal staff. Confirm the participant's organization and invitation context, compare profile details, and contact the protected employee through a known channel. Name formatting differences or stale identity records can also produce misleading matches.

## Detection blind spots
The hunt requires `CloudAppEvents` participant-detail telemetry and current `IdentityInfo` group membership. It performs an exact, case-sensitive join after replacing periods in `AccountName`; different capitalization, middle initials, whitespace, aliases, Unicode lookalikes, or other display-name variations can evade matching. It also depends on the configured group names and does not protect users outside those groups.

## Validation
This hunt has not yet been validated with a controlled external Teams account. Replace the group placeholders, test an external participant whose display name exactly matches a protected user, verify the resulting participant fields, and measure collisions involving legitimate guests before promotion beyond draft.

## References
- [MITRE ATT&CK T1036.005: Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [Microsoft Defender XDR advanced hunting schema: CloudAppEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table)
- [Microsoft Defender XDR advanced hunting schema: IdentityInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-identityinfo-table)

