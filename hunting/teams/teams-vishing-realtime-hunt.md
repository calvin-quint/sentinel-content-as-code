---
id: teams-vishing-realtime-hunt
title: Teams Vishing Real-Time Detection (Identity Spoofing + Post-Compromise Signals)
tactic: Initial Access, Discovery, Command and Control
technique: T1566.002, T1082, T1016, T1105, T1071.001
sub_technique_name: Near-real-time candidate combining spoofed-identity delivery with chain-gated post-compromise behavior
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
  last_run: '2026-07-20'
  result: fired as expected
owner: calvin
last_reviewed: '2026-07-20'
analytics_rule: null
---

# Teams Vishing Real-Time Detection (Identity Spoofing + Post-Compromise Signals)

## Summary
Near-real-time candidate combining the rare, high-confidence delivery
signals (native Teams impersonation classifier, plus a direct
roster-name match for a spoofed Service Desk/Infra identity via Teams
chat or call) with rare, high-confidence post-compromise behavior
(a recon burst or curl-based payload staging following an unsanctioned
RMM launch, gated to a prior spoofed contact for the same user).
Deliberately excludes the standalone RMM-launch stage itself — that
generates routine noise from legitimate tool use and belongs in a
separate scheduled hygiene query for human triage, not a real-time
alerting rule (see
[`unsanctioned-rmm-launch-standalone.md`](../endpoint/unsanctioned-rmm-launch-standalone.md)).
The LOLRMM-derived exe list is still computed internally, since the
recon/curl stages need it to define their correlation windows — it
just isn't surfaced as its own output row here.

## Hypothesis
The native Teams impersonation classifier alone misses a meaningful
class of real spoofed-identity contact: an external tenant account
whose display name is set to match a real internal Service Desk/Infra
staff member's name, without tripping Microsoft's own brand/name
classifier. Directly matching external Teams chat/call participants'
display names against the current internal IT roster closes that gap.
Gating the recon/curl stages on either signal (rather than surfacing
them independently) is what keeps this tight enough for near-real-time
use instead of a scheduled hunt.

## Threat intelligence context
No named actor, malware family, or campaign — this targets the general
class of cross-tenant Teams helpdesk/identity-spoofing vishing rather
than one tracked group. The direct roster-name-match approach (as
opposed to relying solely on the native classifier) is what caught a
real spoofed-identity campaign in this tenant, spanning multiple
events over several days — the native classifier did not catch it;
this roster-match approach did.

## Query

**Sentinel**
```kusto
let _Lookback = 14d;
let _TenantId = "00000000-0000-0000-0000-0000000000a1";
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
let _UnsanctionedRMMExes =
    toscalar(
        union LOLRMM_FromFilename, LOLRMM_FromPaths
        | distinct Name, RmmExe
        | summarize make_set(RmmExe)
    );
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
    | extend
        ImpersonationDisplayName = tostring(RawEventData.Sender.DisplayName),
        ImpersonationUPN         = tostring(RawEventData.Sender.UPN),
        ImpersonationType        = tostring(RawEventData.ImpersonationType),
        ImpactedUserUPN          = tostring(RawEventData.UserId)
    | extend
        EventTime      = Timestamp,
        EventType      = strcat("[TEAMS_IMPERSONATION:", ImpersonationType, "] Cross-tenant lure"),
        Actor          = ImpactedUserUPN,
        Detail         = strcat(
                           "ImpersonatorName=", ImpersonationDisplayName,
                           " | ImpersonatorUPN=", ImpersonationUPN,
                           " | Type=", ImpersonationType
                         ),
        KillChainPhase = "Delivery - Teams Social Engineering"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
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
        Timestamp        = min(Timestamp),
        AccountId        = any(AccountId),
        ExternalNames     = make_set_if(MemberDisplayName, MemberOrgId != _TenantId),
        ExternalUPNs      = make_set_if(MemberUPN, MemberOrgId != _TenantId),
        ExternalOrgIds    = make_set_if(MemberOrgId, MemberOrgId != _TenantId),
        InternalTargetUPNs = make_set_if(MemberUPN, MemberOrgId == _TenantId)
        by GroupKey
    | extend
        SpoofDisplayName = tostring(ExternalNames[0]),
        SpoofUPN         = tostring(ExternalUPNs[0]),
        SpoofOrgId       = tostring(ExternalOrgIds[0]),
        TargetUPN        = tostring(InternalTargetUPNs[0])
    | where isnotempty(SpoofDisplayName) and isnotempty(TargetUPN)
    | project Timestamp, AccountId, SpoofDisplayName, SpoofUPN, SpoofOrgId, TargetUPN, EventSource = "ChatCreated";
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
        Timestamp        = min(Timestamp),
        AccountId        = any(AccountId),
        ExternalNames     = make_set_if(AttendeeDisplayName, isnotempty(AttendeeOrgId) and AttendeeOrgId != _TenantId),
        ExternalUPNs      = make_set_if(AttendeeUPN, isnotempty(AttendeeOrgId) and AttendeeOrgId != _TenantId),
        ExternalOrgIds    = make_set_if(AttendeeOrgId, isnotempty(AttendeeOrgId) and AttendeeOrgId != _TenantId),
        InternalTargetUPNs = make_set_if(AttendeeUPN, AttendeeOrgId == _TenantId)
        by GroupKey
    | extend
        SpoofDisplayName = tostring(ExternalNames[0]),
        SpoofUPN         = tostring(ExternalUPNs[0]),
        SpoofOrgId       = tostring(ExternalOrgIds[0]),
        TargetUPN        = tostring(InternalTargetUPNs[0])
    | where isnotempty(SpoofDisplayName) and isnotempty(TargetUPN)
    | project Timestamp, AccountId, SpoofDisplayName, SpoofUPN, SpoofOrgId, TargetUPN, EventSource = "CallOrMeeting";
let T_SpoofedSDInfraIdentity =
    union T_SpoofedSDInfraViaChat, T_SpoofedSDInfraViaCall
    | join kind=inner (SDInfraUsers | project NormalizedDisplayName, SpoofedRealAccount = AccountUpn)
        on $left.SpoofDisplayName == $right.NormalizedDisplayName
    | extend
        EventTime      = Timestamp,
        EventType      = strcat("[SPOOFED_SD_INFRA_IDENTITY:", EventSource, "] ", SpoofDisplayName),
        Actor          = TargetUPN,
        Detail         = strcat(
                           "SpoofedName=", SpoofDisplayName,
                           " | ExternalActorUPN=", SpoofUPN,
                           " | ExternalTenantId=", SpoofOrgId,
                           " | ChatOrCallInitiator=", AccountId,
                           " | RealAccountBeingSpoofed=", SpoofedRealAccount,
                           " | ActualInternalTarget=", TargetUPN
                         ),
        KillChainPhase = "Delivery - Teams Identity Spoofing"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
let _chainWindow = 6h;
let ImpersonationContact =
    union
        (T_TeamsImpersonation | project ContactTime = EventTime, Actor),
        (T_SpoofedSDInfraIdentity | project ContactTime = EventTime, Actor)
    | summarize ContactTime = min(ContactTime) by Actor;
let _reconWindow = 10m;
let _rmmByDevice =
    DeviceProcessEvents
    | where Timestamp > ago(_Lookback)
    | where FileName in~ (_UnsanctionedRMMExes)
    | project DeviceName, RMMTime = Timestamp, RmmTool = FileName;
let T_ReconBurst =
    DeviceProcessEvents
    | where Timestamp > ago(_Lookback)
    | where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "nslookup.exe",
                           "systeminfo.exe", "ipconfig.exe", "ping.exe", "net.exe", "net1.exe",
                           "arp.exe", "route.exe", "nltest.exe", "tasklist.exe", "hostname.exe")
    | where ProcessCommandLine has_any (
        "whoami", "whoami /all", "whoami /groups", "whoami /priv",
        "nltest", "net user", "net localgroup", "query user",
        "ipconfig /all", "arp -a", "route print", "nslookup",
        "systeminfo", "ping ", "net start", "tasklist", "hostname")
        or FileName in~ ("nslookup.exe", "systeminfo.exe", "ipconfig.exe", "ping.exe",
                          "net.exe", "net1.exe", "arp.exe", "route.exe", "nltest.exe",
                          "tasklist.exe", "hostname.exe")
        or (FileName =~ "cmd.exe" and trim(@"['""\s]+", ProcessCommandLine) =~ "cmd.exe")
    | project DeviceName, ReconTime = Timestamp, ReconCmd = ProcessCommandLine,
              ReconProc = FileName, ReconActor = InitiatingProcessAccountUpn
    | join kind=inner _rmmByDevice on DeviceName
    | where ReconTime between (RMMTime .. (RMMTime + _reconWindow))
    | join kind=inner (ImpersonationContact | project Actor, ContactTime) on $left.ReconActor == $right.Actor
    | where ReconTime between (ContactTime .. (ContactTime + _chainWindow))
    | extend
        EventTime      = ReconTime,
        EventType      = strcat("[RECON_POST_RMM:CHAIN_CONFIRMED] after ", RmmTool),
        Actor          = ReconActor,
        Detail         = strcat("Device=", DeviceName, " | Proc=", ReconProc, " | Cmd=", ReconCmd,
                                 " | PriorSpoofedContact=", format_datetime(ContactTime, 'yyyy-MM-dd HH:mm')),
        KillChainPhase = "Reconnaissance"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
let T_CurlUsage =
    DeviceProcessEvents
    | where Timestamp > ago(_Lookback)
    | where FileName =~ "curl.exe" or ProcessVersionInfoOriginalFileName =~ "curl.exe"
    | extend
        Flag_Silent      = iff(ProcessCommandLine has_any (" -s ", " --silent", " -sS"), "[SILENT] ", ""),
        Flag_OutputFile  = iff(ProcessCommandLine has_any (" -o ", " -O ", " --output"), "[WRITES_FILE] ", ""),
        Flag_InsecureTLS = iff(ProcessCommandLine has_any (" -k ", " --insecure"), "[TLS_BYPASS] ", ""),
        Flag_RawIP       = iff(ProcessCommandLine matches regex @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[RAW_IP_TARGET] ", ""),
        Flag_FromRMM     = iff(InitiatingProcessFileName in~ (_UnsanctionedRMMExes), "[SPAWNED_BY_RMM] ", "")
    | where Flag_Silent != "" or Flag_OutputFile != "" or Flag_InsecureTLS != ""
        or Flag_RawIP != "" or Flag_FromRMM != ""
    | join kind=leftouter _rmmByDevice on DeviceName
    | extend WithinRmmWindow = iff(isnotempty(RMMTime) and Timestamp between (RMMTime .. (RMMTime + 30m)), "[WITHIN_30M_OF_RMM] ", "")
    | join kind=inner (ImpersonationContact | project Actor, ContactTime) on $left.InitiatingProcessAccountUpn == $right.Actor
    | where Timestamp between (ContactTime .. (ContactTime + _chainWindow))
    | extend
        EventTime      = Timestamp,
        EventType      = strcat(Flag_Silent, Flag_OutputFile, Flag_InsecureTLS, Flag_RawIP, Flag_FromRMM, WithinRmmWindow, "curl.exe execution [CHAIN_CONFIRMED]"),
        Actor          = InitiatingProcessAccountUpn,
        Detail         = strcat(
                           "Device=", DeviceName,
                           " | Parent=", InitiatingProcessFileName,
                           " | Cmd=", ProcessCommandLine,
                           " | PriorSpoofedContact=", format_datetime(ContactTime, 'yyyy-MM-dd HH:mm')
                         ),
        KillChainPhase = "Installation - Payload Staging / C2"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
union isfuzzy=true
    T_TeamsImpersonation,
    T_SpoofedSDInfraIdentity,
    T_ReconBurst,
    T_CurlUsage
| where isnotempty(EventTime)
| extend IsSDInfraUser = Actor in ((SDInfraUsers | project AccountUpn))
| order by EventTime asc
```
(No Defender XDR variant — `CloudAppEvents` and `IdentityInfo` are
Sentinel-only tables.)

## Analytics rule configuration
Not present yet — this is documented as a near-real-time candidate but
has not been formalized with a `queryFrequency`/`queryPeriod`/GUID.
Before promoting to a scheduled analytics rule, drop `_Lookback` to
something closer to the intended `queryPeriod` (e.g. 1h) rather than
running the full 14-day window on every scheduled execution.

## What a hit looks like
A `[TEAMS_IMPERSONATION]` or `[SPOOFED_SD_INFRA_IDENTITY]` row for a
user, ideally followed within a few hours by a
`[RECON_POST_RMM:CHAIN_CONFIRMED]` or `curl.exe execution
[CHAIN_CONFIRMED]` row for the same `Actor`. `IsSDInfraUser` flags
whether the *target* is IT staff — it's a descriptive column, not a
hard filter, since the confirmed real recon/curl hits in this hunt's
history were non-IT users and would be silently dropped by a hard
`where Actor in (SDInfraUsers)` filter.

## False positive notes
The native classifier (`T_TeamsImpersonation`) can occasionally flag a
legitimate cross-tenant brand mention; the roster-match stage
(`T_SpoofedSDInfraIdentity`) is the higher-precision signal since it
requires an exact display-name match against current internal IT
staff. `T_CurlUsage`/`T_ReconBurst` are already gated to a prior
contact, which removes nearly all routine noise — remaining false
positives are almost always a legitimate contact (a real MSP/vendor
whose name coincidentally matches internal naming) rather than the
recon/curl stage itself.

## Detection blind spots
`T_RMMLaunch` is intentionally excluded as a real-time signal (too
noisy on its own) — a chain that goes straight from spoofed contact to
recon/curl without an intermediate RMM launch is still caught here, but
one that relies on RMM as the *only* post-contact action produces no
row in this specific query (see the full hunt and the RMM-specific
chain-gated variant for that coverage). The 6-hour chain window is wide
enough to cover contact → RMM launch → recon/curl even though the RMM
launch itself isn't surfaced, but a slower attacker operating beyond
that window evades the gate entirely.

## Validation
All stages tested against live tenant data. `T_SpoofedSDInfraIdentity`
confirmed a real spoofed-identity vishing campaign spanning multiple
events across several days in this tenant — the roster-match approach
caught it where the native classifier (`T_TeamsImpersonation`) did not.
`T_TeamsImpersonation` was separately confirmed against a distinct real
brand-impersonation event. `T_ReconBurst` and `T_CurlUsage` were
confirmed against two real, already-remediated payload-staging
incidents.

No public Atomic Red Team test models this exact multi-stage,
chain-gated pattern — validation here is against real observed
incidents rather than simulated ART tests.

## References
- Full, ungated hunt this is derived from: [`teams-helpdesk-impersonation-hunt.md`](teams-helpdesk-impersonation-hunt.md)
- Chain-gated single-link variants: [`spoofed-contact-then-recon.md`](spoofed-contact-then-recon.md), [`spoofed-contact-then-rmm.md`](spoofed-contact-then-rmm.md), [`spoofed-call-live-window-then-curl.md`](spoofed-call-live-window-then-curl.md)
- MITRE ATT&CK: [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1016](https://attack.mitre.org/techniques/T1016/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
