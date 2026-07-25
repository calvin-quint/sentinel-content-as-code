---
id: unsanctioned-rmm-launch-standalone
title: Unsanctioned RMM Launch Detection (Standalone, Ungated)
tactic: Command and Control
technique: T1219
sub_technique_name: Remote Access Software
severity: low
confidence: low
status: production
platforms:
- sentinel
data_sources:
- DeviceProcessEvents
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
last_reviewed: '2026-07-19'
analytics_rule: null
---

# Unsanctioned RMM Launch Detection (Standalone, Ungated)

## Summary
Org-wide, ungated feed of every launch of an RMM tool not on the
approved list, resolved live against the LOLRMM catalog. Extracted from
the spoofed-Teams-contact chain hunt with the impersonation gate
removed, for broad periodic review rather than as a firing alert.

## Hypothesis
Not a behavioral anomaly detector — this is a hygiene/inventory feed.
Its value is surfacing every unsanctioned RMM launch org-wide so a
human can periodically review the list, not flagging any single launch
as suspicious on its own. It will fire on routine legitimate tool use
(QuickAssist, GoToAssist, WinSCP, PuTTY, and similar) and needs human
triage per hit; use the chain-gated variant
([`spoofed-contact-then-rmm.md`](../teams/spoofed-contact-then-rmm.md))
for a low-noise, higher-confidence signal suitable for tighter
alerting.

## Threat intelligence context
No named actor, malware family, or campaign — targets the broad,
ongoing trend of RMM-tool abuse across many different threat actors and
intrusion types, not one specific campaign.

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
DeviceProcessEvents
| where Timestamp > ago(_Lookback)
| where FileName in~ (_UnsanctionedRMMExes)
| extend FileNameLower = tolower(FileName)
| lookup kind=leftouter (LOLRMM_Executables | distinct RmmExe, Name | extend RmmExeLower = tolower(RmmExe)) on $left.FileNameLower == $right.RmmExeLower
| project
    EventTime          = Timestamp,
    EventType          = strcat("[RMM_LAUNCH] ", coalesce(Name, FileName)),
    Actor              = InitiatingProcessAccountUpn,
    Device             = DeviceName,
    RmmTool            = FileName,
    LOLRMM_Name        = coalesce(Name, "unmatched"),
    ProcessCommandLine,
    KillChainPhase     = "Installation - Unsanctioned Tool"
| order by EventTime desc
```
(No Defender XDR variant as written — the `externaldata` LOLRMM catalog
pull is a Sentinel-only operator; the underlying
`DeviceProcessEvents` filter would work in Defender XDR if the
approved-exe list were hardcoded instead.)

Scope filters (append as needed):
```kusto
| where Device startswith "corp-"     // corporate devices only
| where Device startswith "vendor-"   // third-party contractor devices only
| where LOLRMM_Name != "unmatched"    // drop rows that only matched via an approved-name exclusion gap
```

## What a hit looks like
Not a single "hit" pattern — this is a review feed. `LOLRMM_Name`
identifies the specific matched tool; a device/account pair appearing
repeatedly with the same tool over time is more consistent with
routine (if unsanctioned) use than a one-off launch, which deserves
closer attention.

## False positive notes
This is the expected/default state for most rows: legitimate use of a
remote-access tool that simply isn't on the sanctioned list yet
(QuickAssist, GoToAssist, WinSCP, PuTTY, and similar are common
sources). Maintain the `_AllowedRMMNames` exclusion list as tools get
formally approved, rather than treating every row here as an incident.

## Detection blind spots
Entirely ungated — carries no signal about intent, so it cannot
distinguish a help-desk tech's routine session from an attacker's. Also
limited to whatever the LOLRMM catalog currently lists; a brand-new or
rebranded RMM tool not yet in the feed produces no row here until the
catalog is updated. For a version that filters this down to a
high-confidence signal, see
[`spoofed-contact-then-rmm.md`](../teams/spoofed-contact-then-rmm.md).

## Validation
Not applicable in the usual sense — this is a hygiene/inventory feed,
not a behavior-based detection with a specific attack to simulate.
Confirmed the LOLRMM feed resolves correctly and that the four
approved-name exclusions are real, legitimate noise sources worth
excluding.

## References
- Chain-gated, higher-confidence variant: [`spoofed-contact-then-rmm.md`](../teams/spoofed-contact-then-rmm.md)
- Companion install-time detection: [`unsanctioned-rmm-install-detection.md`](../../rules/analytics/endpoint/unsanctioned-rmm-install-detection.md)
- Existing curated-list variant (static deny-list, no live catalog pull): [`remote-access-software-unauthorized-rmm.md`](../../rules/analytics/endpoint/remote-access-software-unauthorized-rmm.md)
- MITRE ATT&CK: [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Software)
