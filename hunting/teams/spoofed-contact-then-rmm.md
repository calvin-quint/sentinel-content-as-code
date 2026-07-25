---
id: spoofed-contact-then-rmm
title: Spoofed Teams Contact Followed by Unsanctioned RMM Launch
tactic: Initial Access, Command and Control
technique: T1566.002, T1219
sub_technique_name: Spearphishing Voice / Remote Access Software
severity: high
confidence: medium
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
  last_run: null
  result: null
owner: calvin
last_reviewed: '2026-07-20'
analytics_rule: null
---

# Spoofed Teams Contact Followed by Unsanctioned RMM Launch

## Summary
Narrow, chain-gated hunt: only surfaces an unsanctioned RMM tool launch
if the same user also had a spoofed Teams contact (native
`TeamsImpersonationDetected`, or a roster-name match against current
Service Desk/Infra staff) within the preceding window. Gating on the
prior contact is what makes this usable as a real-time-adjacent signal
— the ungated RMM-launch stage fires constantly on routine legitimate
tool use and needs a separate periodic-review query (see
[`unsanctioned-rmm-launch-standalone.md`](../endpoint/unsanctioned-rmm-launch-standalone.md)).

## Hypothesis
A brand-new RMM tool launch, on its own, is common enough (QuickAssist,
WinSCP, PuTTY, and similar legitimate tools all match the same
LOLRMM-driven exclusion list) that alerting on every instance is
unusable without a gate. Requiring a spoofed Teams contact for the same
user in the preceding hours removes nearly all of that noise, since
legitimate tool use has no such contact — while still catching the
specific pattern this exists to catch: a caller impersonating IT
talking a victim into launching remote-access software.

## Threat intelligence context
No named actor, malware family, or campaign — targets the general
vishing/helpdesk-impersonation pattern (spoofed contact followed by a
talked-into RMM install) rather than one tracked group.

## Query

**Sentinel**
```kusto
let _Lookback = 14d;
let _TenantId = "00000000-0000-0000-0000-0000000000a1";
let _chainWindow = 6h;
let _AllowedRMMNames = dynamic([
    "Splashtop",
    "Atera",
    "mstsc.exe (Microsoft Remote Desktop Connection)",
    "CentraStage (Now Datto)"
]);
let LOLRMM =
    externaldata(
        Name:string, Category:string, Description:string, Author:string,
        Date:datetime, LastModified:datetime, Website:string, Filename:string,
        OriginalFileName:string, PEDescription:string, Product:string,
        Privileges:string, Free:string, Verification:string, SupportedOS:string,
        Capabilities:string, Vulnerabilities:string, InstallationPaths:string,
        Artifacts:string, Detections:string, References:string, Acknowledgement:string
    ) ["https://lolrmm.io/api/rmm_tools.csv"] with (format="csv", ignoreFirstRecord=True);
let LOLRMM_FromFilename =
    LOLRMM
    | where Name !has_any (_AllowedRMMNames)
    | mv-expand FilenameCandidate = split(Filename, ",")
    | extend FilenameCandidate = trim(@"\s+", tostring(FilenameCandidate))
    | where isnotempty(FilenameCandidate) and FilenameCandidate endswith ".exe"
    | where FilenameCandidate !~ "Installer.exe"
    | project Name, RmmExe = FilenameCandidate;
let LOLRMM_FromPaths =
    LOLRMM
    | where Name !has_any (_AllowedRMMNames)
    | mv-expand PathCandidate = split(InstallationPaths, ",")
    | extend PathCandidate = trim(@"\s+", tostring(PathCandidate))
    | extend RmmExe = tostring(split(PathCandidate, @"\")[-1])
    | where isnotempty(RmmExe) and RmmExe endswith ".exe"
    | where RmmExe !~ "Installer.exe"
    | project Name, RmmExe;
let LOLRMM_Executables =
    union LOLRMM_FromFilename, LOLRMM_FromPaths
    | distinct Name, RmmExe;
let _UnsanctionedRMMExes = toscalar(LOLRMM_Executables | summarize make_set(RmmExe));
let _SDInfraGroupNames = dynamic(["IT-Infrastructure-Group", "IT-ServiceDesk-Group"]);
let SDInfraUsers =
    IdentityInfo
    | summarize arg_max(TimeGenerated, *) by AccountUpn
    | where GroupMembership has_any (_SDInfraGroupNames)
    | extend NormalizedDisplayName = replace_string(AccountName, ".", " ")
    | project AccountUpn, NormalizedDisplayName;
let T_TeamsImpersonation =
    CloudAppEvents
    | where Timestamp > ago(_Lookback)
    | where ActionType == "TeamsImpersonationDetected"
    | extend ImpactedUserUPN = tostring(RawEventData.UserId)
    | project ContactTime = Timestamp, Actor = ImpactedUserUPN,
              ContactDetail = strcat("NativeClassifier | Impersonator=", tostring(RawEventData.Sender.DisplayName));
let T_SpoofedSDInfraViaChat =
    CloudAppEvents
    | where Timestamp > ago(_Lookback)
    | where Application == "Microsoft Teams"
    | where ActionType == "ChatCreated"
    | where tobool(RawEventData.ParticipantInfo.HasForeignTenantUsers) == true
    | extend GroupKey = tostring(RawEventData.ChatThreadId)
    | mv-expand Member = RawEventData.Members
    | extend
        MemberDisplayName = tostring(Member.DisplayName),
        MemberUPN         = tostring(Member.UPN),
        MemberOrgId       = tostring(Member.OrganizationId)
    | summarize
        Timestamp = min(Timestamp),
        ExternalNames = make_set_if(MemberDisplayName, MemberOrgId != _TenantId),
        ExternalUPNs  = make_set_if(MemberUPN, MemberOrgId != _TenantId),
        InternalTargetUPNs = make_set_if(MemberUPN, MemberOrgId == _TenantId)
        by GroupKey
    | extend
        SpoofDisplayName = tostring(ExternalNames[0]),
        SpoofUPN         = tostring(ExternalUPNs[0]),
        TargetUPN        = tostring(InternalTargetUPNs[0])
    | where isnotempty(SpoofDisplayName) and isnotempty(TargetUPN)
    | project Timestamp, SpoofDisplayName, SpoofUPN, TargetUPN, EventSource = "ChatCreated";
let T_SpoofedSDInfraViaCall =
    CloudAppEvents
    | where Timestamp > ago(_Lookback)
    | where Application == "Microsoft Teams"
    | where ActionType in ("CallParticipantDetail", "MeetingParticipantDetail")
    | extend GroupKey = coalesce(tostring(RawEventData.CallId), tostring(RawEventData.MeetingDetailId))
    | where isnotempty(GroupKey)
    | mv-expand Attendee = RawEventData.Attendees
    | extend
        AttendeeDisplayName = tostring(Attendee.DisplayName),
        AttendeeUPN         = tostring(Attendee.UPN),
        AttendeeOrgId       = tostring(Attendee.OrganizationId)
    | summarize
        Timestamp = min(Timestamp),
        ExternalNames = make_set_if(AttendeeDisplayName, isnotempty(AttendeeOrgId) and AttendeeOrgId != _TenantId),
        ExternalUPNs  = make_set_if(AttendeeUPN, isnotempty(AttendeeOrgId) and AttendeeOrgId != _TenantId),
        InternalTargetUPNs = make_set_if(AttendeeUPN, AttendeeOrgId == _TenantId)
        by GroupKey
    | extend
        SpoofDisplayName = tostring(ExternalNames[0]),
        SpoofUPN         = tostring(ExternalUPNs[0]),
        TargetUPN        = tostring(InternalTargetUPNs[0])
    | where isnotempty(SpoofDisplayName) and isnotempty(TargetUPN)
    | project Timestamp, SpoofDisplayName, SpoofUPN, TargetUPN, EventSource = "CallOrMeeting";
let T_SpoofedSDInfraIdentity =
    union T_SpoofedSDInfraViaChat, T_SpoofedSDInfraViaCall
    | join kind=inner (SDInfraUsers | project NormalizedDisplayName, SpoofedRealAccount = AccountUpn)
        on $left.SpoofDisplayName == $right.NormalizedDisplayName
    | project ContactTime = Timestamp, Actor = TargetUPN,
              ContactDetail = strcat("RosterMatch:", EventSource, " | SpoofedName=", SpoofDisplayName,
                                      " | ExternalUPN=", SpoofUPN, " | RealAccountSpoofed=", SpoofedRealAccount);
let ImpersonationContact =
    union T_TeamsImpersonation, T_SpoofedSDInfraIdentity
    | summarize arg_min(ContactTime, ContactDetail) by Actor;
DeviceProcessEvents
| where Timestamp > ago(_Lookback)
| where FileName in~ (_UnsanctionedRMMExes)
| extend FileNameLower = tolower(FileName)
| lookup kind=leftouter (LOLRMM_Executables | distinct RmmExe, Name | extend RmmExeLower = tolower(RmmExe)) on $left.FileNameLower == $right.RmmExeLower
| join kind=inner (ImpersonationContact | project Actor, ContactTime, ContactDetail)
    on $left.InitiatingProcessAccountUpn == $right.Actor
| where Timestamp between (ContactTime .. (ContactTime + _chainWindow))
| extend IsSDInfraUser = InitiatingProcessAccountUpn in ((SDInfraUsers | project AccountUpn))
| project
    EventTime      = Timestamp,
    EventType      = strcat("[RMM_LAUNCH:CHAIN_CONFIRMED] ", coalesce(Name, FileName)),
    Actor          = InitiatingProcessAccountUpn,
    Device         = DeviceName,
    RmmTool        = FileName,
    LOLRMM_Name    = coalesce(Name, "unmatched"),
    ProcessCommandLine,
    PriorSpoofedContact = format_datetime(ContactTime, 'yyyy-MM-dd HH:mm'),
    ContactDetail,
    IsSDInfraUser,
    KillChainPhase = "Delivery -> Installation (confirmed chain)"
| order by EventTime asc
```
(No Defender XDR variant — `CloudAppEvents` and `IdentityInfo` are
Sentinel-only tables.)

## What a hit looks like
A launch of an RMM tool not on the approved list (`_AllowedRMMNames`),
resolved against the live LOLRMM catalog, where the same user had a
spoofed Teams contact within the preceding 6 hours. `LOLRMM_Name`
identifies the matched tool; `PriorSpoofedContact`/`ContactDetail`
identify the gating contact.

## False positive notes
A user contacting a real external MSP/vendor for legitimate support,
where that vendor's display name happens to coincidentally match
internal IT naming, could satisfy the gate — check `ContactDetail`'s
`ExternalUPN` and cross-reference against known legitimate external
support relationships before escalating. New entries to `LOLRMM` (or
internal tools not yet added to `_AllowedRMMNames`) can also produce
noise; review `LOLRMM_Name = "unmatched"` rows for exactly this.

## Detection blind spots
Only fires if the launch happens within `_chainWindow` (6h) of the
contact and by the same account — a slower attacker who waits longer,
or who pivots to a second compromised account before launching the RMM
tool, evades this specific gate. Also limited to whatever the LOLRMM
catalog currently lists; a brand-new or rebranded RMM tool not yet in
the feed is invisible to this query until the catalog is updated.

## Validation
No public Atomic Red Team test models the full "spoofed contact then
RMM launch" chain — individual RMM tool execution has some T1219
coverage in ART for specific named tools, but not gated on a prior
social-engineering contact. Validate manually: simulate a spoofed
external Teams contact against a test account, then launch a
LOLRMM-listed (non-approved) RMM binary from that account within the
chain window and confirm the rule fires.

## References
- Companion hunts: [`spoofed-call-live-window-then-curl.md`](spoofed-call-live-window-then-curl.md), [`spoofed-contact-then-recon.md`](spoofed-contact-then-recon.md)
- Ungated variant (broad periodic review, no contact gate): [`unsanctioned-rmm-launch-standalone.md`](../endpoint/unsanctioned-rmm-launch-standalone.md)
- MITRE ATT&CK: [T1566.002](https://attack.mitre.org/techniques/T1566/002/) (Spearphishing Voice), [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Software)
