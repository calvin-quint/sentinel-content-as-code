---
id: spoofed-call-live-window-then-curl
title: Spoofed Teams Call Live Window Followed by curl.exe
tactic: Initial Access, Command and Control
technique: T1566.002, T1105, T1071.001
sub_technique_name: Spearphishing Voice / Ingress Tool Transfer / Web Protocols
severity: high
confidence: high
status: production
platforms:
- sentinel
data_sources:
- CloudAppEvents
- DeviceProcessEvents
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
  last_run: '2026-07-21'
  result: fired as expected
owner: calvin
last_reviewed: '2026-07-21'
analytics_rule: null
---

# Spoofed Teams Call Live Window Followed by curl.exe

## Summary
Chain-gated hunt: flags `curl.exe` execution that falls inside the live
`JoinTime`–`LeaveTime` window of a Teams call where the external
caller's display name matches a current Service Desk/Infrastructure
staff member's real name. Gating on the actual call window — extracted
directly from `RawEventData`, not the outer `CloudAppEvents` timestamp
— is what makes this precise enough to use without heavy manual
triage.

## Hypothesis
The outer `Timestamp` field on `CallParticipantDetail`/
`MeetingParticipantDetail` rows tracks closer to audit-record creation
time than to when the call actually happened, so gating on it produces
a misleading timeline. Extracting `JoinTime`/`LeaveTime` directly from
`RawEventData` and requiring curl execution to fall inside that live
window (plus a short trailing buffer for hangup-to-retry lag) is a much
tighter correlation — confirmed against real incidents where every
payload download happened during an active call's screen-share window,
never before or after it.

## Threat intelligence context
No named actor, malware family, or campaign — this targets the general
class of voice-guided social engineering (a caller impersonating IT
talking a victim through running a command live) rather than one
tracked group.

## Query

**Sentinel**
```kusto
let _Lookback = 14d;
let _TenantId = "00000000-0000-0000-0000-0000000000a1";
let _trailingBuffer = 10m;
let _SDInfraGroupNames = dynamic(["IT-Infrastructure-Group", "IT-ServiceDesk-Group"]);
let SDInfraUsers =
    IdentityInfo
    | summarize arg_max(TimeGenerated, *) by AccountUpn
    | where GroupMembership has_any (_SDInfraGroupNames)
    | extend NormalizedDisplayName = replace_string(AccountName, ".", " ")
    | project AccountUpn, NormalizedDisplayName;
let SpoofedCallWindows =
    CloudAppEvents
    | where Timestamp > ago(_Lookback)
    | where Application == "Microsoft Teams"
    | where ActionType in ("CallParticipantDetail", "MeetingParticipantDetail")
    | extend
        GroupKey  = coalesce(tostring(RawEventData.CallId), tostring(RawEventData.MeetingDetailId)),
        JoinTime  = todatetime(RawEventData.JoinTime),
        LeaveTime = todatetime(RawEventData.LeaveTime)
    | where isnotempty(GroupKey)
    | mv-expand Attendee = RawEventData.Attendees
    | extend
        AttendeeDisplayName = tostring(Attendee.DisplayName),
        AttendeeUPN         = tostring(Attendee.UPN),
        AttendeeOrgId       = tostring(Attendee.OrganizationId)
    | summarize
        JoinTime  = min(JoinTime),
        LeaveTime = max(LeaveTime),
        ExternalNames = make_set_if(AttendeeDisplayName, isnotempty(AttendeeOrgId) and AttendeeOrgId != _TenantId),
        ExternalUPNs  = make_set_if(AttendeeUPN, isnotempty(AttendeeOrgId) and AttendeeOrgId != _TenantId),
        InternalTargetUPNs = make_set_if(AttendeeUPN, AttendeeOrgId == _TenantId)
        by GroupKey
    | extend
        SpoofDisplayName = tostring(ExternalNames[0]),
        SpoofUPN         = tostring(ExternalUPNs[0]),
        TargetUPN        = tostring(InternalTargetUPNs[0])
    | where isnotempty(SpoofDisplayName) and isnotempty(TargetUPN)
    | where LeaveTime > JoinTime
    | join kind=inner (SDInfraUsers | project NormalizedDisplayName, SpoofedRealAccount = AccountUpn)
        on $left.SpoofDisplayName == $right.NormalizedDisplayName
    | project GroupKey, JoinTime, LeaveTime, Actor = TargetUPN, SpoofDisplayName, SpoofUPN, SpoofedRealAccount;
DeviceProcessEvents
| where Timestamp > ago(_Lookback)
| where FileName =~ "curl.exe" or ProcessVersionInfoOriginalFileName =~ "curl.exe"
| extend
    Flag_Silent      = iff(ProcessCommandLine has_any (" -s ", " --silent", " -sS"), "[SILENT] ", ""),
    Flag_OutputFile  = iff(ProcessCommandLine has_any (" -o ", " -O ", " --output"), "[WRITES_FILE] ", ""),
    Flag_InsecureTLS = iff(ProcessCommandLine has_any (" -k ", " --insecure"), "[TLS_BYPASS] ", ""),
    Flag_RawIP       = iff(ProcessCommandLine matches regex @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[RAW_IP_TARGET] ", "")
| extend CurlActorLower = tolower(InitiatingProcessAccountUpn)
| join kind=inner (SpoofedCallWindows | extend ActorLower = tolower(Actor)) on $left.CurlActorLower == $right.ActorLower
| where Timestamp between (JoinTime .. (LeaveTime + _trailingBuffer))
| extend IsSDInfraUser = InitiatingProcessAccountUpn in ((SDInfraUsers | project AccountUpn))
| project
    EventTime      = Timestamp,
    EventType      = strcat(Flag_Silent, Flag_OutputFile, Flag_InsecureTLS, Flag_RawIP, "curl.exe [LIVE_CALL_CONFIRMED]"),
    Actor          = InitiatingProcessAccountUpn,
    Device         = DeviceName,
    FullCmd        = ProcessCommandLine,
    CallJoinTime   = format_datetime(JoinTime, 'yyyy-MM-dd HH:mm:ss'),
    CallLeaveTime  = format_datetime(LeaveTime, 'yyyy-MM-dd HH:mm:ss'),
    SpoofDisplayName,
    SpoofUPN,
    SpoofedRealAccount,
    IsSDInfraUser,
    KillChainPhase = "Delivery (Live Voice) -> Installation - Payload Staging"
| order by EventTime asc
```
(No Defender XDR variant — `CloudAppEvents` and `IdentityInfo` are
Sentinel-only tables.)

## What a hit looks like
A `curl.exe` execution timestamped between an external caller's
`JoinTime` and `LeaveTime` (plus a 10-minute buffer), where the
caller's display name matched a real current Service Desk/Infra staff
member's name but the account itself was external. `IsSDInfraUser` on
the output flags whether the *target* is IT staff — real confirmed
hits were non-IT users. `Flag_OutputFile`/`Flag_InsecureTLS`/
`Flag_RawIP` in `EventType` narrow further toward payload-staging-shaped
curl calls specifically.

## False positive notes
A legitimate co-browsing/support call where a real (non-spoofed)
Service Desk tech walks a user through a curl-based diagnostic during
a live screen share would also fall inside a call window — the
`SpoofedRealAccount` join is what rules most of these out, since it
requires the *external* caller's name to match internal IT staff
naming, not just any call. Verify the external UPN's tenant ID against
known partner/MSP tenants before escalating.

## Detection blind spots
Only catches curl execution timed to fall within the live call window
itself — a delayed payload retrieval after hangup (beyond the trailing
buffer) or delivery via a different tool (`Invoke-WebRequest`,
`certutil`, a browser download) is not caught by this query. Also blind
to calls where `RawEventData` is missing the external attendee's
organization ID, since the external-name extraction filters on
`isnotempty(AttendeeOrgId)`.

## Validation
No public Atomic Red Team test models "victim runs curl during a live
voice-guided call" — this is social-engineering behavior, not a
technique ART simulates directly. Empirically validated against
confirmed real incidents: this hunt's `JoinTime`/`LeaveTime` gating
correctly bounded curl execution to inside the call window in every
case, after an earlier version gating on the outer `Timestamp` field
had produced a misleading timeline.

## References
- Companion hunts: [`spoofed-contact-then-recon.md`](spoofed-contact-then-recon.md), [`spoofed-contact-then-rmm.md`](spoofed-contact-then-rmm.md)
- MITRE ATT&CK: [T1566.002](https://attack.mitre.org/techniques/T1566/002/) (Spearphishing Voice), [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Web Protocols)
