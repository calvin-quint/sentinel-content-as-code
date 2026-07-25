---
id: unsanctioned-rmm-install-detection
title: Unsanctioned RMM Install Detection (LOLRMM-Driven)
tactic: Command and Control, Persistence
technique: T1219, T1543.003
sub_technique_name: Remote Access Software / Create or Modify System Process - Windows Service
severity: medium
confidence: high
status: production
platforms:
- sentinel
data_sources:
- DeviceFileEvents
- DeviceEvents
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
analytics_rule:
  id: 4f3570a4-45a2-4dc9-8b72-866495eb095f
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics:
  - CommandAndControl
  - Persistence
  relevantTechniques:
  - T1219
  - T1543.003
  entityMappings:
  - entityType: Host
    fieldMappings:
    - identifier: Name
      columnName: DeviceName
  - entityType: File
    fieldMappings:
    - identifier: Name
      columnName: RmmExe
  incidentConfiguration:
    createIncident: true
    groupingConfiguration:
      enabled: true
      reopenClosedIncident: false
      lookbackDuration: PT5H
      matchingMethod: AllEntities
  eventGroupingSettings:
    aggregationKind: SingleAlert
owner: calvin
last_reviewed: '2026-07-19'
---

# Unsanctioned RMM Install Detection (LOLRMM-Driven)

## Summary
Fires on the first-seen signal for an unsanctioned RMM tool — a binary
dropped to disk, or a Windows service registered for one — resolved
live against the LOLRMM catalog rather than a static curated list.
Companion to the launch-based hunt
([`unsanctioned-rmm-launch-standalone.md`](../../../hunting/endpoint/unsanctioned-rmm-launch-standalone.md)):
this rule is the higher-fidelity, lower-volume half of the pair, since
a brand-new unsanctioned RMM agent landing on disk or registering a
service is inherently abnormal, unlike routine repeated use of an
already-installed remote-access utility.

## Hypothesis
Repeated *launches* of an unsanctioned RMM tool are common enough (help
desk staff, contractors, and legitimate one-off support sessions all
generate them) that alerting on every launch is unusable without a
gate. The *install* event — a new binary appearing on disk, or a new
Windows service being registered for one — is a much rarer, higher-
signal event: it only happens once per tool per device, and a brand-new
unsanctioned remote-access agent appearing on a device has almost no
routine first-party explanation.

## Threat intelligence context
No named actor, malware family, or campaign — targets the broad,
ongoing trend of RMM-tool abuse across many different threat actors and
intrusion types, not one specific campaign.

## Query

**Sentinel**
```kusto
let _Lookback = 1d;
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
let T_FileDrop =
    DeviceFileEvents
    | where Timestamp > ago(_Lookback)
    | where ActionType == "FileCreated"
    | where FileName in~ (_UnsanctionedRMMExes)
    | extend FileNameLower = tolower(FileName)
    | lookup kind=leftouter (LOLRMM_Executables | distinct RmmExe, Name | extend RmmExeLower = tolower(RmmExe)) on $left.FileNameLower == $right.RmmExeLower
    | summarize
        FirstSeen    = min(Timestamp),
        LastSeen     = max(Timestamp),
        DropCount    = count(),
        FolderPaths  = make_set(FolderPath),
        Accounts     = make_set(InitiatingProcessAccountName),
        SampleAccount = any(InitiatingProcessAccountName)
      by DeviceName, RmmExe = FileNameLower, LOLRMM_Name = coalesce(Name, "unmatched")
    | extend
        EventType      = strcat("[RMM_FILE_DROP] ", LOLRMM_Name),
        KillChainPhase = "Installation - Binary Drop";
let T_ServiceInstall =
    DeviceEvents
    | where Timestamp > ago(_Lookback)
    | where ActionType == "ServiceInstalled"
    | extend Fields = parse_json(AdditionalFields)
    | extend
        ServiceName      = tostring(Fields.ServiceName),
        ServiceImagePath = tostring(Fields.ImagePath)
    | where isnotempty(ServiceImagePath)
    | extend ImageFileName = tolower(tostring(split(trim(@"[\s""]+", ServiceImagePath), @"\")[-1]))
    | extend ImageFileName = trim_end(@"\s.*", ImageFileName)
    | join kind=inner (LOLRMM_Executables | distinct RmmExe, Name | extend ImageFileName = tolower(RmmExe)) on ImageFileName
    | summarize
        FirstSeen     = min(Timestamp),
        LastSeen      = max(Timestamp),
        InstallCount  = count(),
        ServiceNames  = make_set(ServiceName),
        ImagePaths    = make_set(ServiceImagePath),
        SampleAccount = any(ImageFileName)
      by DeviceName, RmmExe = ImageFileName, LOLRMM_Name = coalesce(Name, "unmatched")
    | extend
        EventType      = strcat("[RMM_SERVICE_INSTALL] ", LOLRMM_Name),
        KillChainPhase = "Installation - Service Persistence";
union isfuzzy=true T_FileDrop, T_ServiceInstall
| order by LastSeen desc
```
(No Defender XDR variant as written — the `externaldata` LOLRMM catalog
pull is a Sentinel-only operator; the underlying `DeviceFileEvents`/
`DeviceEvents` filters would work in Defender XDR if the approved-exe
list were hardcoded instead.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Command and Control, Persistence — T1219, T1543.003 |
| Entity mappings | `Host.Name = DeviceName` · `File.Name = RmmExe` |
| Incident grouping | All entities, 5h lookback |

Note: `_Lookback` is set to `1d` to match `queryPeriod` (`P1D`), unlike
the ad-hoc hunt variants in this repo which use a 14-day window for
manual review. Because each scheduled run only evaluates the prior day,
"first-seen" here means first-seen-in-the-last-24h, not first-ever —
an install event just outside a run boundary could theoretically be
missed if the schedule is disrupted; this is an accepted trade-off for
running as a real-time alert rather than a periodic hunt.

## What a hit looks like
A `DeviceName`/`RmmExe` pair with `EventType` either
`[RMM_FILE_DROP]` or `[RMM_SERVICE_INSTALL]` (or both, across separate
rows — higher confidence together) for a tool not on the approved list.
`LOLRMM_Name` identifies the matched catalog entry; `FolderPaths`/
`ImagePaths` show where it landed.

## False positive notes
A help desk tech legitimately installing a new (not-yet-approved) RMM
tool for a specific support engagement is the expected source of noise.
Maintain `_AllowedRMMNames` as tools get formally approved, and route
confirmed-legitimate installs through a suppression rule rather than
deleting them from the base detection, so genuinely new unapproved
tools are still caught.

## Detection blind spots
Only matches binaries the live LOLRMM catalog currently lists —
`Installer.exe` is deliberately excluded as a known generic-filename
false-positive source (some catalog entries list it as a generic
filename, flooding this rule with routine MSI `/repair` operations);
this is a known gap under separate investigation, not a fix. A
brand-new or rebranded RMM tool not yet in the catalog, or an attacker
renaming/dropping the binary under a name that doesn't match the
catalog's `Filename`/`InstallationPaths` fields, evades this rule
entirely.

## Validation
No confirmed Atomic Red Team test identified for this exact
catalog-driven, install-time detection. Validate manually: drop a
LOLRMM-listed (non-approved) RMM binary to disk, or register a Windows
service pointing at one, on a lab device and confirm the rule fires.

## References
- Companion launch-based hunt (ungated, higher volume): [`unsanctioned-rmm-launch-standalone.md`](../../../hunting/endpoint/unsanctioned-rmm-launch-standalone.md)
- Chain-gated launch variant (gated to a prior spoofed Teams contact): [`spoofed-contact-then-rmm.md`](../../../hunting/teams/spoofed-contact-then-rmm.md)
- Existing curated-list variant (static deny-list, no live catalog pull): [`remote-access-software-unauthorized-rmm.md`](remote-access-software-unauthorized-rmm.md)
- MITRE ATT&CK: [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Software), [T1543.003](https://attack.mitre.org/techniques/T1543/003/) (Create or Modify System Process: Windows Service)
