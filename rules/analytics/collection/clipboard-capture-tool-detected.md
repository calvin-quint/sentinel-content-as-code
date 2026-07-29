---
id: clipboard-capture-tool-detected
title: Clipboard Capture Tool Dropped and Persisted
tactic: Collection
technique: T1115, T1547.001
sub_technique_name: Clipboard Data / Registry Run Keys Persistence
severity: medium
confidence: medium
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceProcessEvents, DeviceRegistryEvents]
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
  id: a3fd29f9-91e7-439b-a1c9-4a024425b948
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [Collection]
  relevantTechniques: [T1115, T1547.001]
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
last_reviewed: "2026-07-29"
---

# Clipboard Capture Tool Dropped and Persisted

## Summary
Detects known clipboard-utility binaries (Ditto, ClipboardFusion, CLCL,
ArsClip, ClipX, Clipboard Master) launching from a user-writable path
(`AppData`, `ProgramData`, `Temp`, `Users\Public`), plus the matching
registry footprint — a Run-key or app-specific key referencing one of
those binaries — that gives one persistence.  These are legitimate,
often open-source, clipboard-history tools with a real install base,
which is exactly why they're an attractive repurposing target: a
genuine Ditto install is unremarkable, but a spoofed-publisher copy
dropped by an MSI to a temp path is not.

## Hypothesis
A legitimate clipboard-history tool is normally installed deliberately
by IT or a user via a signed installer to a standard `Program Files`
location and shows up once, not repeatedly staged via an installer to a
user-writable temp path. Combining "known clipboard-tool binary name"
with "launched from a location a normal install wouldn't use" narrows
this from "someone uses Ditto" (common, benign) to "something is
staging a clipboard tool the way a dropped payload would" (rare,
worth review). Clipboard capture is a low-noise, high-value collection
technique against credential managers, crypto wallets, and copy-pasted
one-time codes, and doesn't require any network activity to function —
it can sit silent for a long time before it's noticed any other way.

## Threat intelligence context
No named actor, malware family, or campaign tied to this rule
generically, but directly informed by IR-2026-004 (this repo's own
incident): a repurposed, legitimate open-source Ditto build (spoofed
publisher "Microsoft") was dropped via a malicious MSI
(`windtupdates.msi`) to
`C:\Users\<user>\AppData\Local\Ditto\Ditto.exe`, with `Ditto.lnk`
Startup persistence and 6 supporting DLLs dropped alongside it in the
same `AppData\Local\Ditto\` folder — confirmed via sandbox detonation
as a repurposed legitimate tool, not a custom-built implant. That
incident later confirmed Ditto.exe also drove a second-wave SMB/RPC
coercion sweep from the same host, an important reminder that a
"clipboard tool" hit from this rule should not be dismissed as
collection-only without checking the same device's `DeviceNetworkEvents`
for coercion-interface activity (see the companion
`coercion-attack-rpc-interface-abuse` rule).

## Query

**Sentinel / Defender XDR**
```kusto
let lookback = 1d;
let ClipboardToolNames = dynamic([
    "ditto.exe", "clipboardfusion.exe", "clcl.exe", "arsclip.exe",
    "clipx.exe", "clipboardmaster.exe"
]);
let UserWritablePaths = dynamic([@"\AppData\", @"\ProgramData\", @"\Temp\", @"\Users\Public\"]);
let ProcessHits =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName has_any (ClipboardToolNames)
    | where FolderPath has_any (UserWritablePaths)
    | where InitiatingProcessFileName !in~ ("explorer.exe")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath,
              ProcessCommandLine, InitiatingProcessFileName,
              EventType = "ClipboardTool_ProcessLaunch";
let PersistenceHits =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any (@"\Run\", @"\RunOnce\") or RegistryKey has "Software\\Ditto"
    | where RegistryKey has_any (ClipboardToolNames) or RegistryValueData has_any (ClipboardToolNames)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              FileName = InitiatingProcessFileName, FolderPath = RegistryKey,
              ProcessCommandLine = RegistryValueData, InitiatingProcessFileName,
              EventType = "ClipboardTool_RegistryPersistence";
ProcessHits
| union PersistenceHits
| order by Timestamp desc
```
Same query works unchanged in Defender XDR advanced hunting and
Sentinel — both tables are shared MDE-sourced schemas.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Collection — T1115 · Persistence — T1547.001 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` · `File.Name = FileName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `ClipboardTool_ProcessLaunch` row where `InitiatingProcessFileName` is
an installer/scripting process (`msiexec.exe`, `powershell.exe`,
`cmd.exe`) rather than direct user interaction, combined with a
`ClipboardTool_RegistryPersistence` row for the same `DeviceName` within
the same session, is the strongest pairing — installer-driven drop plus
immediate persistence matches the confirmed IR-2026-004 pattern exactly.
Pull the file hash and check it against the vendor's actual published
release if in doubt; a repurposed legitimate tool often still passes a
casual AV scan.

## False positive notes
IT-approved rollout of a real clipboard-history tool via an MSI/EXE
installer (including through an RMM or software-deployment pipeline)
will trigger this legitimately, since installers commonly stage files
through `AppData`/`Temp` before final placement. Maintain an
`ApprovedInstallSources` allowlist (deployment tool process name, or a
known internal package repository URL in `ProcessCommandLine`) rather
than excluding the binaries themselves.

## Detection blind spots
The `ClipboardToolNames` list is a fixed allowlist of known tools — a
custom-built or renamed clipboard-capture binary that doesn't match any
of these names produces no signal, and clipboard capture implemented as
a DLL injected into an existing legitimate process (rather than a
standalone binary) is invisible to this rule entirely. The registry
check is similarly name-dependent; a tool using a generic or randomized
key name under `Run` without referencing the binary name in
`RegistryValueData` won't match `RegistryValueData has_any
(ClipboardToolNames)`.

## Validation
No confirmed Atomic Red Team test identified — clipboard-capture tool
staging isn't a technique ART simulates atomically. Validate manually:
in a lab environment, drop a renamed copy of Ditto (or another listed
tool) via `msiexec` to `%LOCALAPPDATA%\Ditto\`, add a Startup shortcut
or Run-key entry pointing to it, and confirm both the process-launch
and registry-persistence rows appear.

## References
- MITRE ATT&CK: [T1115](https://attack.mitre.org/techniques/T1115/) (Clipboard Data), [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Registry Run Keys / Startup Folder)
