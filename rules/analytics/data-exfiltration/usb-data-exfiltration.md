---
id: usb-data-exfiltration
title: USB Mass Storage Bulk File Copy
tactic: Exfiltration
technique: T1052.001
sub_technique_name: Exfiltration Over Physical Medium - Exfiltration over USB
severity: high
confidence: high
status: production
platforms:
- defender_xdr
- sentinel
data_sources:
- DeviceEvents
- DeviceFileEvents
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
analytics_rule:
  id: 17728a44-4783-4ac4-8667-43938e16c7fa
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics:
  - Exfiltration
  relevantTechniques:
  - T1052.001
  entityMappings:
  - entityType: Host
    fieldMappings:
    - identifier: Name
      columnName: DeviceName
---

# USB Mass Storage Bulk File Copy

## Summary
Detects a USB mass-storage device connecting, followed within a
configurable window (default 15 min) by a bulk file copy from the
endpoint exceeding a file-count threshold (default 50). Optional
`DeviceNameToSearch` filter to scope to a specific host during a
targeted investigation.

## Hypothesis
A single or small handful of files copied shortly after a USB drive is
inserted is routine (moving a document, a photo). A bulk copy exceeding
50 files in the same short window after insertion is a materially
different pattern — the volume itself is what suggests deliberate mass
data collection onto removable media rather than incidental use, not any
single file's content.

## Threat intelligence context
No named actor, malware family, or campaign — a generic volume-based
exfiltration-over-USB detection.

## Query

**Defender XDR / Sentinel**
```kusto
let DeviceNameToSearch = ''; // DeviceName to search for. Leave blank to search all devices.
let TimespanInSeconds = 900; // Period of time between device insertion and file copy
let FileCountThreshold = 50;
let Connections =
DeviceEvents
| where (isempty(DeviceNameToSearch) or DeviceName =~ DeviceNameToSearch) and ActionType == "PnpDeviceConnected"
| extend parsed = parse_json(AdditionalFields)
| project DeviceId,ConnectionTime = Timestamp, DriveClass = tostring(parsed.ClassName), UsbDeviceId = tostring(parsed.DeviceId), ClassId = tostring(parsed.DeviceId), DeviceDescription = tostring(parsed.DeviceDescription), VendorIds = tostring(parsed.VendorIds)
| where DriveClass == 'USB' and DeviceDescription == 'USB Mass Storage Device';
DeviceFileEvents
| where (isempty(DeviceNameToSearch) or DeviceName =~ DeviceNameToSearch) and InitiatingProcessAccountName != "system" and FolderPath !startswith "c" and FolderPath !startswith @"\"
| join kind=inner Connections on DeviceId
| where datetime_diff('second',Timestamp,ConnectionTime) <= TimespanInSeconds
| extend af = parse_json(AdditionalFields)
| extend FileSizeBytes = tolong(coalesce(tolong(af["FileSize"]), tolong(af["FileSizeBytes"]), 0))
| summarize TotalCopiedBytes = sum(FileSizeBytes),
            FileCount = count(),
            FirstEvent = min(Timestamp),
            LastEvent = max(Timestamp),
            SampleFile = any(FileName)
  by DeviceId, DeviceName, UsbDeviceId, VendorIds, DeviceDescription
  | where FileCount >= FileCountThreshold
| extend TotalCopiedMB = round(TotalCopiedBytes / (1024.0 * 1024.0), 2)
| project DeviceName,
          UsbDeviceId,
          DeviceDescription,
          VendorIds,
          FileCount,
          TotalCopiedMB,
          FirstEvent,
          LastEvent,
          SampleFile
| order by FileCount desc
```
(Same query works unchanged in both — this uses only shared
`DeviceEvents`/`DeviceFileEvents` schema fields.)

## What a hit looks like
A `DeviceName` with `FileCount` well above the 50-file threshold and a
large `TotalCopiedMB` shortly after `ConnectionTime`. Review
`SampleFile` and the device's `VendorIds` for context, and check
`InitiatingProcessAccountName` (excluded here only for `"system"`) for
who was logged in.

## False positive notes
Legitimate bulk operations — a user backing up a project folder,
transferring media files, or an IT technician imaging/migrating data —
can exceed the 50-file threshold. Tune `FileCountThreshold` and
`TimespanInSeconds` per environment norms if this is noisy for
departments that do legitimate bulk transfers regularly.

## Detection blind spots
Only fires on files copied to paths outside `c:\` (the `FolderPath
!startswith "c"` filter) — a copy to a path structured differently than
expected, or a drive letter other than what this filter anticipates, may
not match correctly. Also depends on `DeviceDescription == 'USB Mass
Storage Device'` exactly — a USB device that identifies itself
differently (some external SSDs, some phones in file-transfer mode)
could evade the `Connections` filter entirely. A slow, deliberate copy
of fewer than 50 files over a longer period than `TimespanInSeconds`
also evades both the volume and timing constraints.

## Validation
No confirmed Atomic Red Team test identified for this exact volume/
timing pattern — T1052.001 exists in ART's technique index, but a
verified specific atomic test match wasn't confirmed. Validate manually:
connect a USB mass storage device to a lab endpoint and copy 50+ files
to it within 15 minutes, then confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/usb_data_exfiltration.kql
- MITRE ATT&CK: [T1052.001](https://attack.mitre.org/techniques/T1052/001/) (Exfiltration over USB)
