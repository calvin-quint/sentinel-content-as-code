---
id: high-score-anomalous-authentication
title: UEBA High Score Anomalous Authentication
tactic: Credential Access, Initial Access, Persistence
technique: T1110, T1078, T1098, T1136
sub_technique_name: null
severity: medium
confidence: high
status: production
platforms:
- sentinel
data_sources:
- Anomalies
- BehaviorAnalytics
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references: []
validated:
  atomic_test: T1110.003-7
  atomic_test_url: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md#atomic-test-7-password-spray-microsoft-online-accounts-with-msolspray-azureo365
  lab_ref: null
  last_run: null
  result: null
analytics_rule:
  id: b20d809c-700e-4eb9-81d3-ab10bb821d95
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
  - CredentialAccess
  - InitialAccess
  - Persistence
  relevantTechniques:
  - T1110
  - T1078
  - T1098
  - T1136
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: FullName
      columnName: UserPrincipalName
    - identifier: Name
      columnName: Account_0_Name
    - identifier: UPNSuffix
      columnName: Account_0_UPNSuffix
owner: calvin
last_reviewed: '2026-07-19'
---

# UEBA High Score Anomalous Authentication

## Summary
Surfaces the highest-confidence UEBA anomaly signals — sign-in, account
lifecycle, and elevated-token activity — into a single ranked view per
user, replacing the noisier built-in "Anomalous Sign-in Activity" gallery
rule.

## Hypothesis
Sentinel's UEBA engine already scores individual events against a
per-entity behavioral baseline; a single anomalous event at a middling
score is common noise, but a UserPrincipalName that clears a 0.5 score
threshold across any of ten specific high-signal anomaly templates
within the same hour is behaving in a way its own baseline doesn't
expect. Joining that against BehaviorAnalytics' InvestigationPriority
and BlastRadius adds the tenant's own severity judgment on top of the
raw anomaly score — the claim is that MaxScore + InvestigationPriority
ranks true risk better than either signal alone.

## Threat intelligence context
No named actor, malware family, or campaign — this is a statistical/
behavioral detection built on Sentinel's built-in UEBA models, not a
threat-intel-driven rule. Included for template completeness, not
because a specific threat maps to it.

## Query

**Sentinel**
```kusto
Anomalies
| where TimeGenerated > ago(1h)
| where Score >= 0.5
| where AnomalyTemplateName in (
    // Identity sign-in anomalies
    "UEBA Anomalous Authentication",
    "UEBA Anomalous Failed Sign-in",
    // Account lifecycle
    "UEBA Anomalous Account Creation",
    "UEBA Anomalous Account Manipulation",
    "UEBA Anomalous Privilege Granted",
    // Token / elevated access — highest confidence signals in tenant
    "Suspicious volume of logins to computer with elevated token",
    "Suspicious volume of logins to user account with elevated token",
    // Spray / stuffing
    "Suspicious volume of logins to user account",
    "Suspicious volume of logins to user account by logon types",
    // Post-compromise cloud activity
    "Anomalous Azure operations"
)
| summarize
    EventCount     = count(),
    MaxScore       = max(Score),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated),
    Descriptions   = make_set(Description, 5),
    SourceIPs      = make_set(SourceIpAddress, 5),
    Locations      = make_set(tostring(SourceLocation), 5),
    AnomalyReasons = make_set(tostring(AnomalyReasons), 5)
    by UserPrincipalName, AnomalyTemplateName,
       Tactics, Techniques
| where isnotempty(UserPrincipalName)
| join kind=leftouter (
    BehaviorAnalytics
    | where TimeGenerated > ago(1h)
    | where isnotempty(UserPrincipalName)
    | extend BlastRadius = tostring(UsersInsights.BlastRadius)
    | summarize
        InvestigationPriority = max(InvestigationPriority),
        BlastRadius           = max(BlastRadius),
        UEBAActivityInsights  = make_set(ActivityInsights, 3)
      by UserPrincipalName
) on UserPrincipalName
| extend
    InvestigationPriority = coalesce(InvestigationPriority, 0),
    BlastRadius           = coalesce(BlastRadius, "Unknown"),
    UEBAActivityInsights  = coalesce(tostring(UEBAActivityInsights), "[]")
| extend
    Account_0_Name      = tostring(split(UserPrincipalName, "@")[0]),
    Account_0_UPNSuffix = tostring(split(UserPrincipalName, "@")[1])
| project
    FirstSeen, LastSeen, UserPrincipalName,
    AnomalyTemplateName, MaxScore, EventCount,
    InvestigationPriority, BlastRadius, UEBAActivityInsights,
    Descriptions, SourceIPs, Locations,
    AnomalyReasons, Tactics, Techniques,
    Account_0_Name, Account_0_UPNSuffix
| sort by MaxScore desc, InvestigationPriority desc
```

(No Defender XDR variant — `Anomalies` and `BehaviorAnalytics` are Sentinel
UEBA tables with no Defender XDR portal equivalent.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `PT1H` |
| Suppression | `PT24H` |
| Grouping | By account, 24h window |
| Entity mappings | `Account.FullName = UserPrincipalName` · `Account.Name = Account_0_Name` · `Account.UPNSuffix = Account_0_UPNSuffix` |
| Custom details | `MaxScore`, `AnomalyTemplateName`, `InvestigationPriority`, `BlastRadius`, `UEBAActivityInsights`, `SourceIPs`, `Locations` |
| Replaces | Anomalous Sign-in Activity (built-in gallery rule) |

## What a hit looks like
A UserPrincipalName appears with `MaxScore >= 0.5` tied to one of the ten
flagged anomaly templates, alongside a non-zero `InvestigationPriority`
and a populated `BlastRadius` from BehaviorAnalytics. High
InvestigationPriority + high BlastRadius + a token/elevated-access
template name (e.g. "Suspicious volume of logins... with elevated
token") is the highest-confidence combination to triage first.

## False positive notes
Threshold was empirically tuned against 30 days of live tenant
telemetry: average score across that period sits at 0.27, with 0.5
chosen as a deliberate margin above normal noise and 0.6 confirmed as
the observed ceiling for benign activity. Score alone can still fire on
legitimate behavior changes (new device, travel, role change) — the
BehaviorAnalytics join and BlastRadius fields exist specifically to help
separate a genuinely elevated-risk account from a one-off environmental
change.

## Detection blind spots
Entirely dependent on Sentinel's UEBA models having enough baseline
history for the account — new hires, recently reactivated accounts, or
low-activity accounts don't have a reliable baseline, so scoring is
unreliable in either direction for them. A patient attacker who stays
inside the account's established behavioral norms (same IP ranges, same
login times, same access patterns) won't trip any of the listed
`AnomalyTemplateName` values — this rule adds no independent detection
logic beyond ranking/correlating what UEBA has already scored, so it
inherits every blind spot of the underlying UEBA models.

## Validation
Not yet tested against a simulated attack. A matching test has been
identified — [T1110.003 Atomic Test #7](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md#atomic-test-7-password-spray-microsoft-online-accounts-with-msolspray-azureo365),
which sprays a single password across Azure AD/O365 accounts via
MSOLSpray — a direct match for the "UEBA Anomalous Failed Sign-in" and
"Suspicious volume of logins to user account" templates this rule
watches. It has not been executed yet; running it against a test tenant
in `offsec-lab` and confirming the rule fires is the next step.

Validation to date is otherwise empirical/production-based: the score
threshold was tuned against 30 days of live tenant data rather than a
lab simulation, which is a different (and weaker) kind of evidence than
an actual attack-simulation run.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/ueba/high_score_anomalous_authentication.kql
- Replaces built-in Sentinel gallery rule: "Anomalous Sign-in Activity"
- MITRE ATT&CK: [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force), [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts), [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation), [T1136](https://attack.mitre.org/techniques/T1136/) (Create Account)
- Matching validation test: [Atomic Red Team T1110.003 Atomic Test #7 — Password Spray Microsoft Online Accounts with MSOLSpray (Azure/O365)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md#atomic-test-7-password-spray-microsoft-online-accounts-with-msolspray-azureo365)
