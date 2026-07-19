---
id: browser-extension-suspicious-install
title: Suspicious Browser Extension Installation
tactic: Persistence
technique: T1176
sub_technique_name: Browser Extensions
severity: high
confidence: medium
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceProcessEvents, DeviceRegistryEvents, DeviceFileEvents]
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
  id: 768df6e3-e68c-4ba8-a358-bc693b069652
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [Persistence]
  relevantTechniques: [T1176]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: AccountName
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

# Suspicious Browser Extension Installation

## Summary
Detects the common malicious browser-extension install vectors —
sideloading an unpacked extension via command-line flags (bypasses
Chrome/Edge Web Store review entirely), forced-install via registry
policy keys written outside the normal Intune/GPO management context,
and extension files dropped into browser profile directories by a
non-browser parent process. Any one of these alone can be legitimate;
the combination of vector + non-standard actor is the actual signal.

## Hypothesis
Each of the three vectors this rule checks (command-line sideload
flags, forced-install policy registry keys, manifest files written by
a non-browser process) has a narrow legitimate explanation — developer
testing, Intune/GPO push, or the browser's own installer. What makes
each vector suspicious specifically is the *actor*: a sideload flag on
a production (non-dev) machine, a policy key written by something other
than the management stack, or a manifest written by PowerShell instead
of the browser's update process. The rule filters for the actor
mismatch, not just the raw vector.

## Threat intelligence context
No named actor, malware family, or campaign — a generic persistence-
via-browser-extension detection applicable to a wide range of adware,
info-stealer, and session-hijacking extension payloads.

## Query

**Defender XDR / Sentinel**
```kusto
let lookback = 1d;

// Vector 1: Browser launched with sideload/unpacked-extension flags - bypasses store review
let SideloadFlags =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ ("chrome.exe", "msedge.exe", "brave.exe")
    | where ProcessCommandLine has_any ("--load-extension", "--disable-extensions-except", "--extensions-on-chrome-urls")
    | project DeviceId, DeviceName, Timestamp, AccountName, FileName,
              ProcessCommandLine, InitiatingProcessFileName, ReportId, Vector = "CommandLineSideload";

// Vector 2: Forced-install registry policy keys written - legit if pushed by the MDM/GPO,
// suspicious if the writing process isn't the management stack
let ForcedInstallRegistry =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where RegistryKey has_any (
        @"Software\Policies\Google\Chrome\ExtensionInstallForcelist",
        @"Software\Policies\Google\Chrome\ExtensionSettings",
        @"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
        @"Software\Policies\Microsoft\Edge\ExtensionSettings",
        @"Software\Policies\Google\Chrome\ExtensionInstallSources",
        @"Software\Policies\Google\Chrome\DeveloperToolsAvailability"
    )
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    // adjust this exclusion list to the actual Intune/MDM management process names
    | where InitiatingProcessFileName !in~ ("mdm.exe", "omadmclient.exe", "gpsvc.exe", "svchost.exe")
    | project DeviceId, DeviceName, Timestamp, AccountName, RegistryKey, RegistryValueData,
              InitiatingProcessFileName, ReportId, Vector = "PolicyRegistryTamper";

// Vector 3: Extension manifest files written by a non-browser process
// (legit installs are written by the browser's own installer/update process, not by
// PowerShell, cmd, or an unrelated script)
let SuspiciousManifestWrite =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where FolderPath has_any (
        @"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\BraveSoftware\Brave-Browser\User Data\"
    )
    | where FolderPath has @"\Extensions\"
    | where FileName =~ "manifest.json"
    | where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "brave.exe", "GoogleUpdate.exe", "MicrosoftEdgeUpdate.exe")
    | project DeviceId, DeviceName, Timestamp, AccountName, FolderPath, FileName,
              InitiatingProcessFileName, ReportId, Vector = "NonBrowserManifestWrite";

SideloadFlags
| union ForcedInstallRegistry, SuspiciousManifestWrite
| summarize FirstSeen = min(Timestamp), Vectors = make_set(Vector), HitCount = count()
    by DeviceName, AccountName
| order by FirstSeen desc
```
(Same query works unchanged in both — this uses only shared
`DeviceProcessEvents`/`DeviceRegistryEvents`/`DeviceFileEvents` schema
fields.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Persistence — T1176 |
| Entity mappings | `Host.Name = DeviceName` · `Account.Name = AccountName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
A `DeviceName`/`AccountName` with one or more `Vectors` populated.
Multiple vectors on the same device/account in the same window is
higher-confidence than a single isolated vector.

## False positive notes
Legitimate enterprise extension deployment via Intune shows up as
SYSTEM/MDM-managed writes — exclude known Intune push accounts/
processes (the `InitiatingProcessFileName !in~` exclusion list needs to
match what's actually deployed in the environment). Developers
intentionally using `--load-extension` for local testing are the other
main source of noise; scope Vector 1 to non-developer machines if
needed.

## Detection blind spots
An extension distributed through the official Web Store (not
sideloaded, not forced via policy) that turns out to be malicious after
the fact — a supply-chain compromise of a previously legitimate
extension, or a store-approved extension that later adds malicious
behavior via an update — produces no signal from any of these three
vectors, since it never triggers sideload flags, forced-install policy
writes, or non-browser manifest writes. This rule only catches the
install-time evasion patterns, not post-install compromise.

## Validation
No confirmed Atomic Red Team test identified — browser extension
sideloading via specific command-line flags isn't modeled as a distinct
ART atomic (T1176 exists as a technique but coverage for this specific
Chrome/Edge flag-based vector wasn't confirmed). Validate manually:
launch Chrome with `--load-extension=<path>` pointing at an unpacked
test extension on a lab device and confirm the rule fires.

## References
- MITRE ATT&CK: [T1176](https://attack.mitre.org/techniques/T1176/) (Browser Extensions)
