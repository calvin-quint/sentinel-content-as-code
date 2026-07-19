---
id: suspicious-browser-installs
title: Suspicious/Unwanted Browser Installs
tactic: Execution
technique: T1204.002
sub_technique_name: User Execution - Malicious File
severity: low
confidence: high
status: production
platforms:
- defender_xdr
- sentinel
data_sources:
- DeviceFileEvents
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
analytics_rule:
  id: 302a49ad-401e-4915-816e-bb623062d770
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
  - Execution
  relevantTechniques:
  - T1204.002
  entityMappings:
  - entityType: Host
    fieldMappings:
    - identifier: Name
      columnName: DeviceName
  - entityType: Account
    fieldMappings:
    - identifier: Name
      columnName: InitiatingProcessAccountName
  - entityType: File
    fieldMappings:
    - identifier: Hash
      columnName: SHA1/SHA256
---

# Suspicious/Unwanted Browser Installs

## Summary
Flags file creation or execution of known PUA-adjacent alternative
browsers/launchers (Wave Browser, Shift, OneLaunch, generic Chromium
repacks) over a 14-day window. These are typically bundled with free-
download installers and used for ad injection, search hijacking, or as a
foothold for follow-on adware — uncommon on managed endpoints and worth
removal plus user follow-up.

## Hypothesis
A small, named set of alternative-browser/launcher products is
consistently associated with bundled-install adware campaigns rather
than deliberate business use. Their presence on a managed endpoint —
identified by product/company version-info metadata rather than just
filename, which is easy to spoof — is a reliable low-severity signal of
a bundled-installer download, not a targeted attack.

## Threat intelligence context
No named actor or campaign — this targets a known category of PUA/
adware-adjacent software rather than a specific threat.

## Query

**Defender XDR / Sentinel**
```kusto
union isfuzzy=true
    DeviceFileEvents,
    DeviceProcessEvents
| where Timestamp > ago(14d)
| where (
    InitiatingProcessVersionInfoCompanyName in~ (
        "Wavesor Software",        // Wave Browser
        "Shift Technologies Inc", // Shift App
        "OneLaunch",              // OneLaunch
        "Chromium Authors"        // Open-source Chromium
    )
    or InitiatingProcessVersionInfoProductName in~ (
        "Wave Browser",
        "Shift",
        "OneLaunch",
        "Chromium"
    )
)
| where ActionType in~ ("CreateFile", "Run", "Start", "Execute", "ProcessCreated")
| summarize
    Count = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    MinTimeGenerated = min(TimeGenerated),
    MinTimestamp = min(Timestamp)
    by
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    FileName,
    InitiatingProcessCommandLine,
    InitiatingProcessVersionInfoProductName,
    InitiatingProcessVersionInfoCompanyName,
    InitiatingProcessParentFileName,
    SHA1,
    SHA256
| project-reorder
    MinTimeGenerated,
    MinTimestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessFolderPath,
    FileName,
    InitiatingProcessCommandLine,
    InitiatingProcessVersionInfoProductName,
    InitiatingProcessVersionInfoCompanyName,
    SHA1,
    SHA256,
    Count,
    FirstSeen,
    LastSeen
| sort by LastSeen desc
```
(Same query works unchanged in both — this uses only shared
`DeviceFileEvents`/`DeviceProcessEvents` schema fields.)

## What a hit looks like
A device/user with file creation or execution events tied to one of the
named products, usually alongside a bundled-installer download in
`InitiatingProcessFolderPath` (Downloads/Temp). Remove the software and
have a quick conversation with the user about what they installed and
from where.

## False positive notes
Legitimate use of open-source Chromium builds (e.g., a developer testing
against vanilla Chromium rather than Chrome/Edge) will match the
`"Chromium Authors"`/`"Chromium"` entries specifically — that's the
noisiest entry in this list by far since Chromium itself isn't
inherently malicious, unlike the other three named products.

## Detection blind spots
Matches on a fixed, named list of products — a new or rebranded PUA
browser not yet added to this list produces no signal. The 14-day window
also means installs older than that won't surface through this specific
query (though the underlying `DeviceFileEvents`/`DeviceProcessEvents`
data would still support a longer manual lookback if needed).

## Validation
No confirmed Atomic Red Team test identified — installing a specific
named PUA browser product isn't a technique ART simulates (T1204.002 is
represented generically in ART via other malicious-file-execution
tests, not this specific software category). Validate manually: install
one of the named products (e.g., a Wave Browser test installer) on a
lab device and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/endpoint/suspicious_browser_installs.kql
- MITRE ATT&CK: [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File)
