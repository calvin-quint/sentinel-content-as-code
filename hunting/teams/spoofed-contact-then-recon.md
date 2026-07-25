---
id: spoofed-contact-then-recon
title: Spoofed Teams Contact Followed by Reconnaissance Commands
tactic: Initial Access, Discovery
technique: T1566.002, T1082, T1016
sub_technique_name: Spearphishing Voice / System Information Discovery / System Network Configuration Discovery
severity: medium
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

# Spoofed Teams Contact Followed by Reconnaissance Commands

## Summary
Narrow, chain-gated hunt: surfaces `whoami`/`nltest`/`net user`/
`ipconfig`-style reconnaissance commands only when the same user also
had a spoofed Teams contact (native impersonation classifier, or a
roster-name match against current Service Desk/Infra staff) within the
preceding window. Deliberately single-link — contact directly to recon
— rather than also requiring an RMM launch in between, since that would
silently miss a case where recon happened via some other access method
(a compromised credential, for example) instead of RMM.

## Hypothesis
Reconnaissance commands (`whoami`, `nltest`, `net user`, `ipconfig
/all`, etc.) are routine enough on their own that alerting on them
ungated is unusable. But the same commands run by a user who was
contacted by a spoofed IT identity in the preceding hours is a much
stronger signal — the contact establishes intent/access, and the recon
commands are consistent with an attacker orienting themselves inside a
freshly gained session.

## Threat intelligence context
No named actor, malware family, or campaign — targets the general
vishing/helpdesk-impersonation pattern (voice or chat contact followed
by hands-on-keyboard reconnaissance) rather than one tracked group.

## Query

**Sentinel**
```kusto
let _Lookback = 14d;
let _TenantId = "00000000-0000-0000-0000-0000000000a1";
let _chainWindow = 6h;
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
| extend ReconActorLower = tolower(InitiatingProcessAccountUpn)
| project DeviceName, ReconTime = Timestamp, ReconCmd = ProcessCommandLine,
          ReconProc = FileName, ReconActor = InitiatingProcessAccountUpn, ReconActorLower,
          ParentProc = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          GrandparentProc = InitiatingProcessParentFileName
| join kind=inner (ImpersonationContact | project Actor, ContactTime, ContactDetail | extend ActorLower = tolower(Actor)) on $left.ReconActorLower == $right.ActorLower
| where ReconTime between (ContactTime .. (ContactTime + _chainWindow))
| extend IsSDInfraUser = ReconActor in ((SDInfraUsers | project AccountUpn))
| project
    EventTime      = ReconTime,
    EventType      = "[RECON:CHAIN_CONFIRMED]",
    Actor          = ReconActor,
    Device         = DeviceName,
    ReconProc,
    ReconCmd,
    ParentProc,
    ParentCmd,
    GrandparentProc,
    PriorSpoofedContact = format_datetime(ContactTime, 'yyyy-MM-dd HH:mm'),
    ContactDetail,
    IsSDInfraUser,
    KillChainPhase = "Delivery -> Reconnaissance (confirmed chain)"
| order by EventTime asc
```
(No Defender XDR variant — `CloudAppEvents` and `IdentityInfo` are
Sentinel-only tables.)

## What a hit looks like
A recon-shaped command (`whoami`, `nltest`, `net user`, etc.) run by a
user who, within the preceding 6 hours, had either a native
`TeamsImpersonationDetected` hit or a chat/call whose external
participant's display name matched a real Service Desk/Infra staff
member. `PriorSpoofedContact`/`ContactDetail` on the output row identify
which contact triggered the gate.

## False positive notes
IT staff legitimately running diagnostic commands shortly after a
routine external vendor/partner call could theoretically satisfy the
gate if that call happens to be misclassified as impersonation — check
`ContactDetail` to confirm the spoofed name genuinely matches internal
IT roster naming (`RosterMatch:*`) rather than a coincidental native
classifier false positive (`NativeClassifier`) before escalating.

## Detection blind spots
Only fires when recon commands are run by the *same* user account that
received the spoofed contact — if the attacker pivots to a different
account (e.g., after credential theft) before running recon, this chain
breaks. Also only covers the specific recon command/binary list defined
here; a scripted recon sequence using unlisted tools would not surface.

## Validation
No public Atomic Red Team test models the full "spoofed Teams contact
then recon" chain specifically — individual recon commands (`whoami`,
`ipconfig`, etc.) have ART coverage under T1082/T1016 individually, but
not gated on a prior social-engineering contact. Validate manually:
simulate a spoofed external Teams contact against a test account, then
run a listed recon command from that account within the chain window
and confirm the rule fires.

## References
- Companion hunts: [`spoofed-call-live-window-then-curl.md`](spoofed-call-live-window-then-curl.md), [`spoofed-contact-then-rmm.md`](spoofed-contact-then-rmm.md)
- MITRE ATT&CK: [T1566.002](https://attack.mitre.org/techniques/T1566/002/) (Spearphishing Voice), [T1082](https://attack.mitre.org/techniques/T1082/) (System Information Discovery), [T1016](https://attack.mitre.org/techniques/T1016/) (System Network Configuration Discovery)
