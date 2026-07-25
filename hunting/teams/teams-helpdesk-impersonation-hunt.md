---
id: teams-helpdesk-impersonation-hunt
title: Teams Helpdesk Impersonation / Cross-Tenant RMM Attack Chain Hunt
tactic: Initial Access, Discovery, Command and Control, Lateral Movement, Exfiltration
technique: T1566.002, T1219, T1082, T1016, T1105, T1071.001, T1021.006, T1567
sub_technique_name: Full-chain hunt spanning delivery through exfiltration
severity: high
confidence: high
status: production
platforms:
- sentinel
data_sources:
- CloudAppEvents
- DeviceProcessEvents
- DeviceNetworkEvents
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

# Teams Helpdesk Impersonation / Cross-Tenant RMM Attack Chain Hunt

## Summary
Full-chain hunt covering the entire observed kill chain: cross-tenant
Teams "helpdesk" impersonation, an unsanctioned RMM tool launch,
post-launch reconnaissance, curl-based payload staging/C2, WinRM
lateral movement, and Rclone-style exfiltration. Every stage is a
`let` block unioned into one output; each stage stands on its own
(nothing here is chain-gated to another stage), so it's meant for
broad, scheduled review rather than as a single high-confidence
alert.

## Hypothesis
No single stage of this chain is reliable enough alone to auto-escalate
(RMM launches are routine, recon commands are routine, curl usage is
routine) — but reviewing all of them together, scoped to current
Service Desk/Infrastructure staff, surfaces the specific multi-stage
pattern this hunt targets: a spoofed IT contact leading a victim
through installing remote-access tooling and running attacker-guided
commands. Stages further downstream in the chain (recon, curl,
lateral movement, exfil) are intentionally left ungated here so a
gap in an earlier stage's detection doesn't silently drop a real hit —
see the chain-gated variants for lower-noise, higher-confidence
versions of the delivery-to-recon and delivery-to-curl links.

## Threat intelligence context
No named actor, malware family, or campaign directly tied to this
hunt — it targets the general 2026-era pattern of cross-tenant Teams
helpdesk/brand impersonation leading into RMM-based access, documented
broadly in industry vishing writeups and cross-tenant impersonation
technique profiles, not one specific tracked group.

## Query

**Sentinel**
```kusto
let _Lookback = 14d;
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
// Sanity check - uncomment to see the resolved exe list before running the full hunt:
// LOLRMM_Executables | order by Name asc
let _SDInfraGroupNames = dynamic(["IT-Infrastructure-Group", "IT-ServiceDesk-Group"]);
let SDInfraUsers =
    IdentityInfo
    | summarize arg_max(TimeGenerated, *) by AccountUpn
    | where GroupMembership has_any (_SDInfraGroupNames)
    | project AccountUpn, AccountDisplayName = AccountName, Department,
              JobTitle, IsAdminAccount = AccountUpn endswith ".admin@contoso.com";
// Uncomment to see just the current SD/Infra roster instead of running the full hunt:
// SDInfraUsers
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
let T_RMMLaunch =
    DeviceProcessEvents
    | where Timestamp > ago(_Lookback)
    | where FileName in~ (_UnsanctionedRMMExes)
    | lookup kind=leftouter (LOLRMM_Executables | distinct RmmExe, Name) on $left.FileName == $right.RmmExe
    | extend
        EventTime      = Timestamp,
        EventType      = strcat("[RMM_LAUNCH] ", coalesce(Name, FileName)),
        Actor          = InitiatingProcessAccountUpn,
        Detail         = strcat(
                           "Device=", DeviceName,
                           " | Tool=", FileName,
                           " | LOLRMM_Name=", coalesce(Name, "unmatched"),
                           " | Cmd=", ProcessCommandLine
                         ),
        KillChainPhase = "Installation - RMM Foothold"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
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
    | extend
        EventTime      = ReconTime,
        EventType      = strcat("[RECON_POST_RMM] after ", RmmTool),
        Actor          = ReconActor,
        Detail         = strcat("Device=", DeviceName, " | Proc=", ReconProc, " | Cmd=", ReconCmd),
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
    | extend
        EventTime      = Timestamp,
        EventType      = strcat(Flag_Silent, Flag_OutputFile, Flag_InsecureTLS, Flag_RawIP, Flag_FromRMM, WithinRmmWindow, "curl.exe execution"),
        Actor          = InitiatingProcessAccountUpn,
        Detail         = strcat(
                           "Device=", DeviceName,
                           " | Parent=", InitiatingProcessFileName,
                           " | Cmd=", ProcessCommandLine
                         ),
        KillChainPhase = "Installation - Payload Staging / C2"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
let _latMoveWindow = 30m;
let T_WinRMLateral =
    DeviceNetworkEvents
    | where Timestamp > ago(_Lookback)
    | where RemotePort in (5985, 5986)
    | project DeviceName, NetTime = Timestamp, RemoteIP, RemotePort,
              Proc = InitiatingProcessFileName, NetActor = InitiatingProcessAccountName
    | join kind=inner _rmmByDevice on DeviceName
    | where NetTime between (RMMTime .. (RMMTime + _latMoveWindow))
    | extend
        EventTime      = NetTime,
        EventType      = "[WINRM_LATERAL] Post-RMM WinRM connection",
        Actor          = NetActor,
        Detail         = strcat("Device=", DeviceName, " | Target=", RemoteIP, ":", tostring(RemotePort), " | Proc=", Proc),
        KillChainPhase = "Lateral Movement"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
let T_ExfilTool =
    DeviceProcessEvents
    | where Timestamp > ago(_Lookback)
    | where FileName =~ "rclone.exe" or ProcessVersionInfoOriginalFileName =~ "rclone.exe"
    | extend
        EventTime      = Timestamp,
        EventType      = "[EXFIL_TOOL] rclone execution",
        Actor          = InitiatingProcessAccountUpn,
        Detail         = strcat("Device=", DeviceName, " | Cmd=", ProcessCommandLine),
        KillChainPhase = "Exfiltration"
    | project EventTime, EventType, Actor, Detail, KillChainPhase;
union isfuzzy=true
    T_TeamsImpersonation,
    T_RMMLaunch,
    T_ReconBurst,
    T_CurlUsage,
    T_WinRMLateral,
    T_ExfilTool
| where isnotempty(EventTime)
| where Actor in ((SDInfraUsers | project AccountUpn))
| order by EventTime asc
```
(No Defender XDR variant — `CloudAppEvents` and `IdentityInfo` are
Sentinel-only tables; `DeviceProcessEvents`/`DeviceNetworkEvents` are
shared schema but the query as written targets Sentinel.)

Drop the `| where Actor in (SDInfraUsers)` line to run org-wide instead
of scoped to Service Desk/Infra — recommended for the curl/exfil/
lateral-movement stages especially, since payload staging and exfil
aren't specific to IT staff; both real confirmed incidents this hunt
caught hit non-IT users. Filter examples:
```kusto
| where EventType contains "[TEAMS_IMPERSONATION]"
| where EventType contains "[RMM_LAUNCH]"
| where EventType contains "[SPAWNED_BY_RMM]"
| where EventType contains "curl.exe"
| where KillChainPhase == "Lateral Movement"
```

## Analytics rule configuration
Not present — this is a broad, multi-stage review query for scheduled
manual triage, not a single-condition auto-firing alert. The two
chain-gated variants ([`spoofed-contact-then-recon.md`](spoofed-contact-then-recon.md),
[`spoofed-contact-then-rmm.md`](spoofed-contact-then-rmm.md)) are the
low-noise pieces of this chain suitable for tighter alerting.

## What a hit looks like
Any row from any of the six stages, scoped to current Service
Desk/Infra staff by default. The most actionable combination is a
`[TEAMS_IMPERSONATION]` or roster-matched spoofed-contact row for a
user followed by an `[RMM_LAUNCH]` and/or `curl.exe execution` row for
the same `Actor` within a few hours — that combination is what every
confirmed real incident looked like.

## False positive notes
Each stage individually carries its own known noise:
- `T_RMMLaunch`: legitimate use of a reviewed, sanctioned remote-access
  tool that isn't yet added to the approved-name exclusion list.
- `T_ReconBurst`: routine IT diagnostic work shortly after a legitimate
  remote-support session.
- `T_CurlUsage`: internal print/appliance management tooling that calls
  an internal IP with `--insecure` (self-signed cert), and third-party
  developer/contractor tooling making local/dev-API calls — both
  learned false-positive patterns, reviewed each run rather than
  blanket-excluded, since blanket exclusion would also hide a real
  attacker reusing the same pattern.
- `T_WinRMLateral` / `T_ExfilTool`: confirmed empty against both real
  incidents caught by this hunt to date — treat any hit here as high
  priority until proven otherwise.

## Detection blind spots
`Installer.exe` is deliberately excluded from the LOLRMM-derived
executable list — some catalog entries list it as a generic filename,
which floods this hunt with false positives against routine MSI
`/repair` operations org-wide. This is a known gap under separate
investigation; do not re-add it without a more specific match (hash,
path, or publisher) to avoid reintroducing the flood. Stages are
independent and ungated, so a real chain that skips a stage entirely
(e.g., direct curl usage with no RMM tool involved) still surfaces on
its own row, but nothing here proves the stages are causally linked —
correlate `Actor` and timing manually, or use the chain-gated variants
for an automated link.

## Validation
- Stage 0 (roster): confirmed against real group membership.
- Stage -1 (LOLRMM): confirmed the feed resolves correctly; the four
  approved-name exclusions were all confirmed as real noise sources.
- Teams impersonation classifier: validated against one real
  `TeamsImpersonationDetected` event, which confirmed the field paths
  and led to dropping an overly narrow keyword filter that would have
  missed it (the real event used no helpdesk-themed keywords at all).
- RMM launch / curl stages: after exclusions, surfaced real findings —
  one confirmed authorized use of a non-approved RMM tool (reviewed),
  and two curl-based payload-staging incidents (both already
  remediated as of this writing).
- Recon burst: tested against the two remediated incidents' devices,
  confirmed clean — no recon commands observed near either RMM
  session.
- WinRM lateral movement / exfil tool: confirmed empty for both
  remediated incidents.

No public Atomic Red Team test models this exact multi-stage chain;
individual stages have partial ART coverage under their respective
techniques (T1219, T1082/T1016, T1105, T1021.006, T1567) run
independently.

## References
- Chain-gated, lower-noise variants: [`spoofed-contact-then-recon.md`](spoofed-contact-then-recon.md), [`spoofed-contact-then-rmm.md`](spoofed-contact-then-rmm.md), [`spoofed-call-live-window-then-curl.md`](spoofed-call-live-window-then-curl.md)
- Near-real-time candidate built from this hunt's highest-confidence stages: [`teams-vishing-realtime-hunt.md`](teams-vishing-realtime-hunt.md)
- MITRE ATT&CK: [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1219](https://attack.mitre.org/techniques/T1219/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1016](https://attack.mitre.org/techniques/T1016/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1021.006](https://attack.mitre.org/techniques/T1021/006/), [T1567](https://attack.mitre.org/techniques/T1567/)
