---
id: "unsanctioned-rmm-tool-execution-via-lolrmm"
title: "Unsanctioned RMM Tool Execution via LOLRMM"
tactic: "Command and Control"
technique: "T1219"
sub_technique_name: "Remote Access Software"
severity: "medium"
confidence: "medium"
status: draft
platforms: [defender_xdr]
data_sources: [DeviceProcessEvents]
sigma_source: null
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references:
    - "https://lolrmm.io/"
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

# Unsanctioned RMM Tool Execution via LOLRMM

## Summary
Identifies execution of remote monitoring and management executables cataloged by LOLRMM while excluding the organization's currently sanctioned products. The hunt dynamically derives executable names from LOLRMM filename and installation-path data and enriches matching Defender process events with the cataloged tool name.

## Hypothesis
Endpoints should execute only approved remote-management products. An executable associated with another RMM platform is more likely to represent unauthorized administration, shadow IT, or attacker use of legitimate remote-access software for persistent command and control.

## Threat intelligence context
This is a behavior and software-inventory hunt rather than a named-threat detection. Threat actors frequently abuse legitimate RMM products because signed software, existing remote-control capabilities, and trusted infrastructure can blend into administrative activity.

## Query

**Defender XDR**
```kusto
// LOOKBACK = 30d
// Source: https://lolrmm.io/api/rmm_tools.csv (direct externaldata pull)
// Sanctioned RMM exclusions are hardcoded until the RMM_Sanctioned_Baseline watchlist exists.
// Reliability note: the live externaldata() dependency can time out if lolrmm.io is
// slow or unavailable. Migrate to a daily-refreshed Watchlist via Logic App or Runbook.
let _Lookback = 30d;
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
    | where not(Name has_any (_AllowedRMMNames))
    | mv-expand FilenameCandidate = split(Filename, ",")
    | extend FilenameCandidate = trim(@"\s+", tostring(FilenameCandidate))
    | where isnotempty(FilenameCandidate) and FilenameCandidate endswith ".exe"
    | where FilenameCandidate !~ "Installer.exe"
    | project Name, RmmExe = FilenameCandidate;
let LOLRMM_FromPaths =
    LOLRMM
    | where not(Name has_any (_AllowedRMMNames))
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
DeviceProcessEvents
| where Timestamp > ago(_Lookback)
| where FileName in~ (_UnsanctionedRMMExes)
| extend FileNameLower = tolower(FileName)
| lookup kind=leftouter (LOLRMM_Executables | distinct RmmExe, Name | extend RmmExeLower = tolower(RmmExe)) on $left.FileNameLower == $right.RmmExeLower
| project
    EventTime          = Timestamp,
    EventType          = strcat("[RMM_EXEC] ", coalesce(Name, FileName)),
    Actor              = InitiatingProcessAccountUpn,
    Device             = DeviceName,
    RmmTool            = FileName,
    LOLRMM_Name        = coalesce(Name, "unmatched"),
    ProcessCommandLine,
    ParentProcess      = InitiatingProcessParentFileName,
    KillChainPhase     = "Installation - Unsanctioned Tool"
| order by EventTime desc
```

## What a hit looks like
Each result identifies the endpoint, initiating user, executable, command line, parent process, and matching LOLRMM product name. Prioritize tools launched by unusual users or parents, installed outside expected paths, recently downloaded, or followed by remote logons, persistence changes, credential access, or lateral movement.

## False positive notes
Portable support tools, vendor-assisted troubleshooting, mergers, pilots, and renamed binaries can produce legitimate matches. Confirm approval and ticket context, compare the file signer and hash with the vendor release, and verify whether the product should be added to the sanctioned baseline. Filename-only matching can collide with unrelated software.

## Detection blind spots
The query depends on live availability and schema stability of the LOLRMM CSV and can fail or time out when the external source is unavailable. It excludes installers, relies primarily on executable names, and will miss renamed binaries, script-only agents, browser-based remote access, tools absent from LOLRMM, and products represented only by non-executable artifacts. Hardcoded sanctioned names can drift from the organization's approved inventory.

## Validation
This hunt has not yet been validated through a controlled RMM deployment. Test with one sanctioned and one unsanctioned product, verify catalog parsing and case-insensitive matching, measure filename collisions, and confirm behavior when the external CSV is unavailable. Replace the live feed with a daily-refreshed watchlist before operationalizing the hunt.

## References
- [MITRE ATT&CK T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [LOLRMM project](https://lolrmm.io/)
- [LOLRMM CSV API](https://lolrmm.io/api/rmm_tools.csv)

