---
id: suspicious-or-weak-elevation-justification
title: "Admin By Request \u2014 Suspicious or Weak Elevation Justification"
tactic: Privilege Escalation
technique: T1548
sub_technique_name: Abuse Elevation Control Mechanism
severity: medium
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
  id: 311ac5e4-e701-42b0-8647-1ea661b9eb2e
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
  - PrivilegeEscalation
  relevantTechniques:
  - T1548
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: user_email_s
  - entityType: Host
    fieldMappings:
    - identifier: Name
      columnName: computer_name_s
---

# Admin By Request — Suspicious or Weak Elevation Justification

## Summary
Flags self-service admin elevation requests approved on a vague,
boilerplate, or policy-bypass-flavored justification ("test", "need
admin", "bypass", "disable"), after excluding known-legitimate recurring
reasons (IDE/docker/collab-tool installs and updates). Also flags short
sessions justified only by generic text when paired with risk signals:
install source in Downloads/Temp, LOLBins in the elevated app list, or
elevation windows of 4+ hours.

## Hypothesis
A legitimate elevation request tends to state a specific, verifiable
task. A justification that's boilerplate, vague, or phrased around
bypassing a control correlates with a user rubber-stamping self-service
elevation rather than describing genuine need — especially when it's
also paired with a risk signal like an install path in Downloads/Temp,
a LOLBin in the elevated app list, or an unusually long elevation
window.

## Threat intelligence context
No named actor, malware family, or campaign — this is an insider-risk/
policy-abuse pattern detection based on justification text, not
threat-intel-driven.

## Query

**Sentinel**
```kusto
AdminByRequestLogs_CL
| where isnotempty(reason_s)
| extend ReasonLower = tolower(trim(" ", reason_s))
| extend SessionHours = iif(
    isnotempty(startTimeUTC_t) and isnotempty(endTimeUTC_t) and tostring(endTimeUTC_t) !has "Invalid",
    datetime_diff('hour', endTimeUTC_t, startTimeUTC_t),
    long(0))
// ── Exclude known legitimate justifications ───────────────────────────────────
| where not(ReasonLower has_any (
    "fix docker", "docker",
    "vs code", "vscode", "visual studio code",
    "ssms", "sql server management",
    "azure cli", "azure data studio",
    "android studio",
    "zoom", "teams", "slack",
    "splashtop",
    "notepad++",
    "ultimaker", "cura",
    "plugin for", "extension for",
    "update ssms", "update vs", "update sql",
    "install ssms", "install vs", "install sql",
    "upgrading", "patching"
))
// ── Flag suspicious justifications ───────────────────────────────────────────
| where ReasonLower in ("test","testing","n/a","na","none","yes","no","ok","okay","sure","work","admin","access","need","required","yep",".","..","...","just because","because","needed","admin session")
    or ReasonLower has_any ("need access","need admin","need it","need this","require access","for work","for my work","to do my job","to do work","work stuff","work related","just testing","just a test","testing abr","no reason","not sure","dont know","routine","routine update","routine maintenance","standard","standard maintenance","standard update","update","install","installation","upgrade","installing a thing","install a thing","need to install","need to update","need to run","have to","must have","should have","install plugin","installing plugin")
    or ReasonLower has_any ("abr","admin by request","adminbyrequest","elevation","elevated","admin rights","admin access","local admin","need admin rights","admin session")
    or ReasonLower has_any ("bypass","workaround","override","disable","turn off","remove policy","remove restriction","get around","avoid","skip","ignore policy")
    or strlen(ReasonLower) <= 10
    or (application_path_s has_any ("\\Downloads\\","\\AppData\\Local\\Temp\\","/Users/","/Downloads") and strlen(ReasonLower) <= 25)
    or (elevatedApplications_s has_any ("silent_install","sc.exe","net.exe","net1.exe","reg.exe","wscript.exe","cscript.exe","mshta.exe") and strlen(ReasonLower) <= 30)
    or (SessionHours >= 4 and strlen(ReasonLower) <= 25)
| project TimeGenerated, reason_s, user_email_s, computer_name_s, application_name_s, application_path_s, elevatedApplications_s, SessionHours, auditlogLink_s
| sort by TimeGenerated desc
```
(No Defender XDR variant — `AdminByRequestLogs_CL` is a Sentinel custom
log table fed by Admin By Request's event API, not a Defender/M365
source.)

## What a hit looks like
A short or vague `reason_s` paired with a risky install path, a LOLBin
in the elevated app list, or a long session window. Check
`computer_name_s` and `application_name_s`/`application_path_s` and
cross-reference against what the user is actually assigned to work on.

## False positive notes
This is heuristic keyword matching, not a deterministic signal —
legitimate use with a terse writing style can still land in the flagged
bucket. The exclusion list already screens common known-legitimate
boilerplate (docker/vscode/collab-tool installs), but any newly adopted
legitimate tool not yet in that list will generate noise until it's
added.

## Detection blind spots
Purely text/keyword based — an attacker or complicit insider who writes
a plausible, specific-sounding justification ("installing approved
diagnostic tool per ticket #1234") bypasses this rule entirely,
regardless of what's actually being installed. The exclusion list is a
manually maintained allowlist: every new legitimate tool adopted by the
org has to be added to it, or it false-positives indefinitely.

## Validation
No public Atomic Red Team test applies — this detects a text/policy-
justification pattern specific to Admin By Request, not a technique ART
simulates. Validate manually: submit an ABR elevation request with a
vague justification ("test") in a lab tenant and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/admin-by-request/suspicious_or_weak_elevation_justification.kql
- MITRE ATT&CK: [T1548](https://attack.mitre.org/techniques/T1548/) (Abuse Elevation Control Mechanism)
