---
id: suspicious-application-elevated-install-detected
title: "Admin By Request \u2014 Suspicious Elevated Application Install"
tactic: Command and Control, Exfiltration, Credential Access
technique: T1219, T1572, T1555, T1567
sub_technique_name: null
severity: high
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- AdminByRequestLogs_CL
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
  id: 2cf324dd-50f8-43a5-a2d5-9a180d8dec31
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
  - T1219
  - T1572
  - T1555
  - T1567
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: Name/UPN
      columnName: User/UserAccount/UserEmail
  - entityType: Host
    fieldMappings:
    - identifier: Name
      columnName: Computer
  - entityType: File
    fieldMappings:
    - identifier: Name/Hash
      columnName: AppName/AppFile, SHA256
---

# Admin By Request — Suspicious Elevated Application Install

## Summary
Flags approved PEDM elevation sessions used to install tooling commonly
abused for remote access (rustdesk/anydesk/teamviewer/vnc), tunneling
(ngrok/zerotier/tailscale), credential harvesting (lazagne/nirsoft
password viewers), or unsanctioned cloud sync/exfil (dropbox/megasync/
rclone). Tiered High/Medium/Low by tool category; installs from temp/
appdata with no vendor metadata are flagged regardless of tool identity.

## Hypothesis
Admin By Request elevation is meant to let users install sanctioned
business software under a controlled, logged process. The risk isn't
whether the elevation itself was approved — it's what gets installed
under it. A tool whose primary or dual-use purpose is remote access,
tunneling, credential harvesting, or unsanctioned sync is a strong
signal of abuse regardless of how the elevation was justified, so this
rule scores the installed tool, not the approval.

## Threat intelligence context
No named actor, malware family, or campaign — this is a dual-use/LOLBin
tool detection built around known abuse categories, not a specific
threat-intel tie.

## Query

**Sentinel**
```kusto
AdminByRequestLogs_CL
| where status_s == "Finished"
| extend ElevatedApps = parse_json(elevatedApplications_s)
| mv-expand ElevatedApp = ElevatedApps
| extend
    DetectedFile   = tolower(coalesce(tostring(ElevatedApp.file),   application_file_s)),
    DetectedName   = tolower(coalesce(tostring(ElevatedApp.name),   application_name_s)),
    DetectedVendor = tolower(coalesce(tostring(ElevatedApp.vendor), application_vendor_s)),
    DetectedPath   = tolower(coalesce(tostring(ElevatedApp.path),   application_path_s)),
    DetectedSHA256 = tostring(coalesce(tostring(ElevatedApp.sha256), application_sha256_s)),
    DetectedScan   = tostring(coalesce(tostring(ElevatedApp.scanResult), application_scanResult_s))
| extend RiskLevel = case(
    DetectedFile has_any ("rustdesk", "ngrok", "anydesk", "zerotier", "localtunnel", "rclone", "megasync", "lazagne", "webbrowserpassview", "mailpassview", "nirsoft", "nircmd", "produkey", "winscp", "filezilla", "cyberduck")
        or DetectedName has_any ("rustdesk", "ngrok", "anydesk", "zerotier", "localtunnel", "rclone", "megasync", "lazagne", "webbrowserpassview", "mailpassview", "nirsoft", "nircmd", "produkey", "winscp", "filezilla", "cyberduck"),
        "High",
    DetectedFile has_any ("dropbox", "box", "icloud", "cloudmounter", "resilio", "synctrayzor", "freefilesync", "tailscale", "hamachi", "teamviewer", "vnc", "ultraviewer")
        or DetectedName has_any ("dropbox", "box", "icloud", "cloudmounter", "resilio", "synctrayzor", "freefilesync", "tailscale", "hamachi", "teamviewer", "vnc", "ultraviewer"),
        "Medium",
    DetectedFile has_any ("wireshark", "npcap", "networkminer", "python", "nodejs", "git-", "veracrypt", "axcrypt")
        or DetectedName has_any ("wireshark", "npcap", "networkminer", "python", "nodejs", "git-", "veracrypt", "axcrypt"),
        "Low",
    (isempty(DetectedVendor) or DetectedVendor == "null") and (DetectedPath has "temp" or DetectedPath has "appdata\\local\\temp"),
        "Medium",
    ""
)
| where isnotempty(RiskLevel)
| extend SuspiciousPath = DetectedPath has_any ("temp", "appdata\\local\\temp", "programdata\\temp", "downloads")
| project
    TimeGenerated,
    RiskLevel,
    SuspiciousPath,
    User         = user_fullName_s,
    UserAccount  = user_account_s,
    UserEmail    = user_email_s,
    Computer     = computer_name_s,
    AppName      = DetectedName,
    AppFile      = DetectedFile,
    AppPath      = DetectedPath,
    AppVendor    = DetectedVendor,
    SHA256       = DetectedSHA256,
    ScanResult   = DetectedScan,
    Reason       = reason_s,
    ABRPolicy    = settingsName_s,
    AuditLogLink = auditlogLink_s
| sort by RiskLevel asc, TimeGenerated desc
```
(No Defender XDR variant — `AdminByRequestLogs_CL` is a Sentinel custom
log table fed by Admin By Request's event API, not a Defender/M365
source.)

## What a hit looks like
A `RiskLevel` of High (rustdesk/ngrok/anydesk/zerotier/lazagne/nirsoft
etc.) on an elevated session warrants same-day triage — pull the user,
computer, SHA256, and `AuditLogLink` and confirm whether the install was
expected. Medium/Low tiers (cloud-sync tools, dev/network utilities) are
lower urgency but still worth a quick check against role and ticket
history.

## False positive notes
Low-tier tools (python, git, wireshark) have plenty of legitimate
developer/IT use — expect noise there. Medium-tier remote-access/sync
tools (teamviewer, dropbox) also have real business use; check
`ABRPolicy`/`Reason` and the requestor's role before escalating rather
than treating every Medium hit as confirmed abuse.

## Detection blind spots
Matching is entirely filename/tool-name string-based (`has_any` against
`DetectedFile`/`DetectedName`) — a renamed binary (`rustdesk.exe` renamed
to `update.exe`) bypasses this rule completely. It also only inspects
the elevation log entry, not actual process behavior after install, and
if Admin By Request changes its logging schema field names, the rule
silently stops matching rather than erroring visibly.

## Validation
No public Atomic Red Team test applies to Admin By Request specifically
— it's a niche PEDM SaaS product ART doesn't model. The underlying
flagged tools (e.g., AnyDesk-style remote access under T1219, rclone-
style exfil under T1567) do have general ART coverage, but not through
the Admin By Request elevation flow itself. Validate manually: run an
approved ABR elevation session in a lab and install one of the flagged
tools, then confirm ingestion and rule fire.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/admin-by-request/suspicious_application_elevated_install_detected.kql
- MITRE ATT&CK: [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Software), [T1572](https://attack.mitre.org/techniques/T1572/) (Protocol Tunneling), [T1555](https://attack.mitre.org/techniques/T1555/) (Credentials from Password Stores), [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service)
