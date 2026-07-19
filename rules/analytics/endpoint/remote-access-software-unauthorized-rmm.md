---
id: remote-access-software-unauthorized-rmm
title: Remote Access Software - Unauthorized RMM Tool Detection
tactic: Command and Control
technique: T1219
sub_technique_name: Remote Access Software
severity: high
confidence: high
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceProcessEvents, DeviceFileEvents]
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
  id: 5b85efba-0f07-4c36-a730-31351cee33d4
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [CommandAndControl]
  relevantTechniques: [T1219]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: AccountName
    - entityType: File
      fieldMappings:
        - identifier: Name
          columnName: FileName
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
last_reviewed: "2026-07-19"
---

# Remote Access Software - Unauthorized RMM Tool Detection

## Summary
Flags installation or execution of remote monitoring & management
tools that are not the sanctioned RMM stack (Atera). RMM abuse has
become one of the most common payload types in 2026 threat reporting —
attackers favor it over custom malware because the binaries are
signed, commonly whitelisted, and rarely trigger AV on their own. This
rule matches a curated list of known RMM tool binary/process names and
excludes the approved Atera footprint.

## Hypothesis
Once an org has standardized on one sanctioned RMM tool, the presence
of any *other* named RMM tool's binary — whether installed or simply
executed — has almost no legitimate first-party explanation. Attackers
increasingly prefer these signed, dual-use tools specifically because
they blend into normal IT-support traffic, so a curated deny-list
approach (rather than trying to detect "remote access behavior"
generically) is the practical way to catch this class of abuse.

## Threat intelligence context
No named actor, malware family, or campaign — this targets the broad
2026-era trend of RMM-tool abuse across many different threat actors
and intrusion types, not one specific campaign.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
// Known RMM tool binaries commonly abused for unauthorized remote access.
// Atera's own binaries (AteraAgent.exe, AgentPackageAtera*.exe, splashtop-streamer under Atera's
// bundled Splashtop) are deliberately excluded below - update names if Atera's installer changes.
let knownRmmBinaries = dynamic([
    "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe",
    "screenconnect.exe", "screenconnect.windowsclient.exe", "connectwisecontrol.exe",
    "logmein.exe", "logmeinrescue.exe", "gotomypc.exe", "g2mcommunicator.exe",
    "rustdesk.exe", "ninjarmm.exe", "ninjaone.exe", "ninjaonemanagement.exe",
    "kaseya.exe", "agentmon.exe", "vsaagent.exe",
    "n-able.exe", "action1_agent.exe", "action1.exe",
    "dwagent.exe", "dwagsvc.exe",           // DWService
    "supremo.exe", "remotepc.exe", "showmypc.exe",
    "splashtopremote.exe", "srmanager.exe"  // standalone Splashtop, not Atera-bundled
]);
// Atera's known process/service footprint - adjust to match what's actually deployed
let approvedAteraBinaries = dynamic([
    "ateraagent.exe", "agentpackageatera.exe", "aterahelpdesk.exe"
]);

let SuspiciousRmmProcess =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where tolower(FileName) in (knownRmmBinaries)
    | where tolower(FileName) !in (approvedAteraBinaries)
    | project DeviceId, DeviceName, Timestamp, AccountName, FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessAccountName, ReportId, Source = "ProcessExecution";

let SuspiciousRmmInstall =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "FileCreated"
    | where tolower(FileName) in (knownRmmBinaries)
    | where tolower(FileName) !in (approvedAteraBinaries)
    | project DeviceId, DeviceName, Timestamp, AccountName = InitiatingProcessAccountName,
              FileName, ProcessCommandLine = InitiatingProcessCommandLine,
              InitiatingProcessFileName, ReportId, Source = "FileWrite";

SuspiciousRmmProcess
| union SuspiciousRmmInstall
| summarize FirstSeen = min(Timestamp), Sources = make_set(Source), HitCount = count()
    by DeviceName, AccountName, FileName
| order by FirstSeen desc
```
(Same query works unchanged in both — this uses only shared
`DeviceProcessEvents`/`DeviceFileEvents` schema fields.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Command and Control — T1219 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` · `File.Name = FileName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` with a `FileName` matching a non-Atera RMM
binary, either installed (`FileWrite`) or executed
(`ProcessExecution`) — or both, which is higher confidence. Confirm
with the user/help desk whether a specific support session explains it.

## False positive notes
A help-desk tech legitimately using a customer's RMM tool during a
vendor support session, or contractors/MSPs using their own approved
tooling, are the expected sources of noise. Maintain an
`ApprovedRMMTools` watchlist and route confirmed-legitimate hits
through a suppression rule rather than deleting them from the base
detection list, so new unapproved tools are still caught.

## Detection blind spots
Only matches the fixed `knownRmmBinaries` list — a newly released RMM
tool, a rebranded/whitelabeled RMM product, or an attacker renaming a
known RMM binary to something else entirely evades this rule (the query
matches on filename, not a more durable signature like a code-signing
certificate thumbprint or hash). If the org's actual Atera footprint
changes (installer update, new binary names), the
`approvedAteraBinaries` exclusion list needs to be updated or Atera
itself starts generating false positives.

## Validation
No confirmed Atomic Red Team test identified for this specific curated-
list detection — general remote-access-software techniques (T1219)
have some ART coverage for individual named tools, but a test matching
this exact "known-bad list minus approved Atera footprint" logic wasn't
confirmed. Validate manually: install or run one of the listed non-
Atera RMM binaries (e.g., a test AnyDesk installer) on a lab device and
confirm the rule fires.

## References
- MITRE ATT&CK: [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Software)
