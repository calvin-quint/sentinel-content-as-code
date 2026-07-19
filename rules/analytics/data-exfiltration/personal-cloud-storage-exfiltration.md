---
id: personal-cloud-storage-exfiltration
title: Personal Cloud Storage Exfiltration
tactic: Exfiltration
technique: T1567.002
sub_technique_name: Exfiltration to Cloud Storage
severity: high
confidence: high
status: production
platforms:
- sentinel
data_sources:
- CloudAppEvents
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
  id: f9127af4-e8db-4a44-b0b2-28c16a1a115f
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
  - T1567.002
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: UserUPN
  - entityType: Host
    fieldMappings:
    - identifier: Name
      columnName: DeviceName
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: IPs
---

# Personal Cloud Storage Exfiltration

## Summary
Final (sixth-iteration) version of this rule — see
[`versions/`](versions/personal-cloud-storage-exfiltration/) for the full
progression from a simple domain check to this DLP-scored form. Flags a
file moving from an org-controlled domain (SharePoint/OneDrive/M365) to
an external target domain where DLP has already tagged the content with
sensitive info types (SSN, credit card, medical, credentials, etc.).
Scores each hit Critical/High/Medium/Low by combining a known high-risk
destination list (Google Drive, Dropbox, Mega, file-sharing/paste sites,
even github.com and claude.ai) with the volume of sensitive-data matches.

## Hypothesis
A file leaving an org-controlled domain is common and often benign on
its own. What actually distinguishes exfiltration from routine business
file-sharing is the combination of (1) DLP already having classified the
content as sensitive and (2) the destination being a known consumer/
anonymous file-sharing service rather than a sanctioned business
partner. Scoring by destination risk tier *and* sensitive-hit volume
together produces a much more actionable Critical/High/Medium/Low split
than either signal alone.

## Threat intelligence context
No named actor, malware family, or campaign — a generic DLP-driven
exfiltration detection applicable to insider risk and account
compromise alike.

## Query

**Sentinel**
```kusto
CloudAppEvents
| where TimeGenerated > ago(1d)
| where ActionType in (
    "FileSyncUploadedFull",
    "FileUploaded",
    "FileUploadedToCloud"
)
// Cheap string pre-filters before parse_json
| where RawEventData has "SensitiveInfoTypeData"
| where RawEventData has "OriginatingDomain"
| where RawEventData has "TargetDomain"
// Now parse — only runs on the small surviving set
| extend Raw = parse_json(RawEventData)
| extend
    OriginatingDomain = tostring(Raw.OriginatingDomain),
    TargetDomain      = tostring(Raw.TargetDomain),
    TargetUrl         = tostring(Raw.TargetUrl)
// Originating from org-controlled source
| where OriginatingDomain has_any (
    "centralparticipant", "sharepoint", "microsoft",
    "office", "contoso"
)
// Targeting something external
| where not(TargetDomain has_any (
    "centralparticipant", "sharepoint", "microsoft",
    "office", "contoso"
))
// DLP signal present and non-empty
| where isnotempty(Raw.SensitiveInfoTypeData)
| extend DLP = Raw.SensitiveInfoTypeData
| where DLP != "" and DLP != "[]"
| mv-expand DLP
| extend
    SensitiveType       = tostring(DLP.SensitiveInfoTypeName),
    SensitiveCount      = toint(DLP.Count),
    SensitiveConfidence = toint(DLP.Confidence)
| where SensitiveType has_any (
    "Social", "Credit", "Address", "Bank",
    "Medical", "License", "Credential"
)
// Risk tier flag for known high-risk destinations
| extend HighRiskDestination = iff(
    TargetUrl has_any (
        "drive.google.com", "docs.google.com", "dropbox.com",
        "box.com", "icloud.com", "onedrive.live.com", "mediafire.com",
        "wetransfer.com", "mega.nz", "mega.io", "sync.com", "pcloud.com",
        "1drv.ms", "storage.live.com", "public-files.live.com",
        "disk.yandex.com", "yadi.sk", "koofr.net", "sendspace.com",
        "zippyshare.com", "anonfiles.com", "pixeldrain.com", "file.io",
        "pastebin.com", "hastebin.com", "ghostbin.com", "paste.ee",
        "proton.me", "protondrive.com", "tresorit.com",
        "github.com", "amazonaws.com", "claude.ai"
    ), true, false
)
| extend
    UserUPN    = tolower(coalesce(
                     iff(AccountId contains "@", AccountId, ""),
                     tostring(Raw.UserId),
                     AccountDisplayName
                 )),
    FileName   = coalesce(
                     iff(isnotempty(ObjectName), ObjectName, ""),
                     tostring(Raw.SourceFileName)
                 ),
    FileExt    = tostring(Raw.SourceFileExtension),
    FileSize   = toint(Raw.FileSyncBytesCommitted),
    DeviceName = tostring(Raw.DeviceName)
| summarize
    FileCount           = dcount(tostring(ObjectId)),
    SensitiveHitCount   = sum(SensitiveCount),
    MaxConfidence       = max(SensitiveConfidence),
    SensitiveTypes      = make_set(SensitiveType),
    FileNames           = make_set(FileName),
    FileExtensions      = make_set(FileExt),
    FileSizes           = make_set(FileSize),
    TargetUrls          = make_set(TargetUrl),
    OriginDomains       = make_set(OriginatingDomain),
    Apps                = make_set(Application),
    IPs                 = make_set(IPAddress),
    HighRiskDestination = max(HighRiskDestination),
    FirstSeen           = min(TimeGenerated),
    LastSeen            = max(TimeGenerated)
by
    UserUPN,
    DeviceName,
    TargetDomain
| where SensitiveHitCount >= 1
| extend RiskScore = case(
    HighRiskDestination == true and SensitiveHitCount >= 10, "Critical",
    HighRiskDestination == true,                             "High",
    SensitiveHitCount >= 10,                                 "Medium",
    "Low"
)
| order by SensitiveHitCount desc
```
(No Defender XDR variant — `CloudAppEvents` is a Sentinel/Defender for
Cloud Apps table.)

## What a hit looks like
`RiskScore == "Critical"` (high-risk destination + 10+ sensitive-data
hits) is the top tier — treat as active exfiltration until proven
otherwise. Review `SensitiveTypes`, `FileNames`, and `TargetUrls`
together to scope what left and where it went.

## False positive notes
Legitimate business use of sanctioned cloud storage (a partner
organization's shared Google Drive, an approved GitHub repo for
non-sensitive code) can still trigger this if DLP misclassifies content
or a file coincidentally matches a sensitive-info pattern. The
`HighRiskDestination` list intentionally includes github.com and
claude.ai — sanctioned developer/AI-tool use will need an explicit
exception process rather than removing those destinations wholesale,
since they're also genuine exfiltration vectors.

## Detection blind spots
Depends entirely on DLP's `SensitiveInfoTypeData` classification having
already fired — content DLP doesn't recognize as sensitive (a novel
data format, a screenshot of sensitive text, an unusual document
structure) produces no `SensitiveHitCount` and is invisible to this
rule regardless of destination. The `OriginatingDomain`/`TargetDomain`
string-matching on `"contoso"` is a placeholder for the org's actual
domain fragment and must be kept current if the org rebrands or adds
domains. Encrypted or password-protected archives uploaded to a
high-risk destination may also evade DLP content inspection entirely.

## Validation
No confirmed Atomic Red Team test identified — DLP-scored cloud
exfiltration with this specific scoring logic isn't a technique ART
simulates directly (closest coverage is generic T1567.002 atomics for
cloud-storage upload, not the DLP-classification layer). Validate
manually: upload a test file containing synthetic sensitive data (e.g.,
a fake SSN pattern) to a high-risk destination like Dropbox from a lab
tenant and confirm the rule fires and scores it correctly.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/personal_cloud_storage_exfiltration.kql
- Full version history (v1-v6): [`versions/personal-cloud-storage-exfiltration/`](versions/personal-cloud-storage-exfiltration/)
- MITRE ATT&CK: [T1567.002](https://attack.mitre.org/techniques/T1567/002/) (Exfiltration to Cloud Storage)
