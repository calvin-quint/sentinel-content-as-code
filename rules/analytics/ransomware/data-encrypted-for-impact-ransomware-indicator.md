---
id: data-encrypted-for-impact-ransomware-indicator
title: Data Encrypted for Impact - Ransomware File Activity Indicator
tactic: Impact
technique: T1486
sub_technique_name: Data Encrypted for Impact
severity: high
confidence: high
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceFileEvents]
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
  id: c3a10807-c2b5-4598-98bc-8a49529531ae
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [Impact]
  relevantTechniques: [T1486]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: File
      fieldMappings:
        - identifier: Name
          columnName: NoteFileName
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

# Data Encrypted for Impact - Ransomware File Activity Indicator

## Summary
Detects the classic ransomware encryption fingerprint — a burst of file
renames on a single device converging on one new, uncommon extension
within a short window — correlated against a ransom-note file (readme/
decrypt-instructions style filename) dropped on the same device around
the same time. Either signal alone is common noise (archivers, batch
converters, AV quarantine); the pairing is what makes this
high-fidelity.

## Hypothesis
Neither a burst of file renames to a new extension nor a single
readme-style file drop is unusual in isolation — both happen for benign
reasons constantly. The combination — 50+ renames to the *same* new
extension within a 10-minute window, on the *same* device, *and* a
ransom-note-patterned file dropped in that same window — is the actual
ransomware fingerprint, since legitimate software has no reason to
produce both signals together.

## Threat intelligence context
No named actor, malware family, or campaign — this targets the
technique's general behavioral fingerprint (mass rename + ransom note),
which is common across nearly all ransomware families regardless of
specific strain.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;
let renameWindow = 10m;
// common benign transient extensions that show up in normal rename bursts - exclude these
let benignExtensions = dynamic(["tmp", "crdownload", "partial", "download", "part"]);
let RenameBursts =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "FileRenamed"
    | where isnotempty(FileName)
    | extend NewExt = tolower(tostring(split(FileName, ".")[-1]))
    | where NewExt !in (benignExtensions)
    | summarize RenameCount = count(), FoldersTouched = dcount(FolderPath)
        by DeviceName, NewExt, bin(Timestamp, renameWindow)
    | where RenameCount >= 50  // tune to the environment's typical background rename rate
    ;
let RansomNoteDrops =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "FileCreated"
    | where FileName matches regex @"(?i)(readme|decrypt|how.?to.?(decrypt|recover)|restore.?files|help.?decrypt).*\.(txt|html|hta)$"
    | project DeviceName, NoteTimestamp = Timestamp, NoteFileName = FileName, FolderPath;

RenameBursts
| join kind=inner (RansomNoteDrops) on DeviceName
| where NoteTimestamp between (Timestamp .. (Timestamp + renameWindow))
| project Timestamp, DeviceName, NewExt, RenameCount, FoldersTouched, NoteFileName, FolderPath
| order by Timestamp desc
```
(Same query works unchanged in both — this uses only shared
`DeviceFileEvents` schema fields.) A standalone fallback — rename burst
alone with no ransom-note correlation captured in-window, for strains
that skip or delay the note — is available as a commented-out,
higher-noise variant in the original `.kql`.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Impact — T1486 |
| Entity mappings | `Host.Name = DeviceName` · `File.Name = NoteFileName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName` with `RenameCount >= 50` converging on one `NewExt`,
paired with a `NoteFileName` dropped within the same 10-minute window.
This is a "isolate the device now, ask questions later" tier hit —
active encryption in progress has a very short remediation window.

## False positive notes
Bulk archive extraction/re-encoding jobs (media transcoding pipelines),
backup software restructuring file extensions, and AV quarantine
renaming (`.vir`/`.quarantine`) are the expected sources of noise.
Exclude known batch-processing service accounts and quarantine
folders, and tune `RenameCount` to the environment's background rename
rate rather than leaving the default untouched.

## Detection blind spots
Requires *both* signals within the same 10-minute window — a
ransomware strain that delays dropping its ransom note well past the
encryption burst, or skips a note entirely (some strains communicate
via a different channel), evades the correlated version and only shows
up in the higher-noise standalone rename-burst fallback. The
`RenameCount >= 50` threshold also means a slower, more targeted
encryption (deliberately throttled to avoid burst-detection) on a
smaller set of high-value files could stay under the threshold
entirely.

## Validation
No confirmed Atomic Red Team test identified — safely simulating actual
file encryption at volume isn't something ART provides test cases for
(for obvious reasons around not damaging test systems). Validate
manually in an isolated lab VM: script a rename burst of 50+ files to a
single new extension within 10 minutes alongside a dropped
readme-style file, and confirm the rule fires — do not run this
against anything but a disposable, isolated test environment.

## References
- MITRE ATT&CK: [T1486](https://attack.mitre.org/techniques/T1486/) (Data Encrypted for Impact)
