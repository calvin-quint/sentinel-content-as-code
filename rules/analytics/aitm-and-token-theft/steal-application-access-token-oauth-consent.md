---
id: steal-application-access-token-oauth-consent
title: Steal Application Access Token - OAuth Consent Phishing
tactic: Credential Access
technique: T1528
sub_technique_name: Steal Application Access Token
severity: high
confidence: medium
status: production
platforms: [sentinel]
data_sources: [AuditLogs]
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
  id: 9a482c18-acf5-43c0-a532-a67c492ac4f1
  kind: Scheduled
  status: Available
  enabled: true
  queryFrequency: PT1H
  queryPeriod: P1D
  triggerOperator: gt
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: PT5H
  tactics: [CredentialAccess]
  relevantTechniques: [T1528]
  entityMappings:
    - entityType: Account
      fieldMappings:
        - identifier: UPN
          columnName: GrantedBy
    - entityType: CloudApplication
      fieldMappings:
        - identifier: Name
          columnName: AppDisplayName
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

# Steal Application Access Token - OAuth Consent Phishing

## Summary
Detects the "illicit consent grant" attack — a user is phished into
granting a malicious (or malicious-looking) OAuth app permissions to
their mailbox/files/directory without any password ever being stolen.
The app then holds a standing token and doesn't need to re-authenticate,
making this persistent and MFA-bypassing by design. Three-part
detection: (1) user consent grants requesting high-risk scopes, (2)
apps with red-flag registration characteristics (unverified publisher,
multi-tenant, newly created), and (3) correlated risk scoring based on
app age at consent.

## Hypothesis
A user consenting to an OAuth app requesting broad, sensitive scopes
(mail, files, directory, offline access) is unremarkable in isolation —
this happens constantly for legitimate SaaS integrations. What
distinguishes the illicit-consent-grant attack is the *combination* of
a high-risk scope request with an app that was registered very recently
relative to when consent was granted — a freshly minted app immediately
asking for broad access is a pattern real, established business tools
essentially never exhibit, since their registration long predates any
individual tenant's consent event.

## Threat intelligence context
No named actor, malware family, or campaign tied to this rule directly
— it targets the general illicit-consent-grant attack class. This is
one of the few rules in the repo where a genuine campaign tie would be
expected if a specific phishing campaign using this vector were
identified; update this section if one is.

## Query

**Sentinel**
```kusto
let lookback = 1d;
let highRiskScopes = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
    "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All", "Sites.ReadWrite.All",
    "Directory.Read.All", "Directory.ReadWrite.All", "User.Read.All", "User.ReadWrite.All",
    "offline_access", "full_access_as_app", "Contacts.Read", "Contacts.ReadWrite"
]);

// Part 1: User (not admin) consent grants requesting at least one high-risk scope
let RiskyConsentGrants =
    AuditLogs
    | where TimeGenerated > ago(lookback)
    | where OperationName in ("Consent to application", "Add OAuth2PermissionGrant", "Add app role assignment to service principal")
    | extend AppDisplayName = tostring(TargetResources[0].displayName)
    | extend ConsentType = tostring(parse_json(tostring(AdditionalDetails))[0].value) // "AllPrincipals" = admin consent, null/user = user consent
    | extend Scopes = tostring(TargetResources[0].modifiedProperties)
    | where Scopes has_any (highRiskScopes)
    | extend GrantedBy = tostring(InitiatedBy.user.userPrincipalName)
    | project TimeGenerated, AppDisplayName, ConsentType, Scopes, GrantedBy,
              CorrelationId, Result;

// Part 2: Red-flag app registration characteristics — newly created app, no verified publisher
// (requires querying the Applications/ServicePrincipal audit trail for creation events)
let NewUnverifiedApps =
    AuditLogs
    | where TimeGenerated > ago(7d)  // wider window — app may have been registered days before the phish lands
    | where OperationName == "Add service principal"
    | extend AppDisplayName = tostring(TargetResources[0].displayName)
    | extend AppId = tostring(TargetResources[0].id)
    | project AppCreatedTime = TimeGenerated, AppDisplayName, AppId;

// Part 3: Correlate — risky consent grant to an app created in the recent past (freshly minted
// apps requesting broad scopes immediately after registration is the highest-fidelity combo)
RiskyConsentGrants
| join kind=leftouter (NewUnverifiedApps) on AppDisplayName
| extend AppAgeAtConsent = TimeGenerated - AppCreatedTime
| extend RiskLevel = case(
    isnotempty(AppCreatedTime) and AppAgeAtConsent < 3d, "Critical - new app + high-risk consent",
    ConsentType == "AllPrincipals", "High - tenant-wide admin consent to high-risk scopes",
    "Medium - user consent to high-risk scopes, app age unknown"
)
| project TimeGenerated, AppDisplayName, GrantedBy, ConsentType, Scopes, AppCreatedTime, RiskLevel, CorrelationId
| order by TimeGenerated desc
```
(No Defender XDR variant — `AuditLogs` is a Sentinel/Entra ID table
with no Defender XDR portal equivalent.)

A fourth, optional correlation step — joining post-consent sign-ins
using the app's token — is documented as a commented-out extension in
the original `.kql` for full attack-chain visibility (consent → first
malicious use); not enabled by default to keep this a single scheduled
query.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Credential Access — T1528 |
| Entity mappings | `Account.UPN = GrantedBy` · `CloudApplication.Name = AppDisplayName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
`RiskLevel == "Critical - new app + high-risk consent"` is the top
tier — an app created within 3 days of receiving a high-risk consent
grant. Review `Scopes` and `GrantedBy` and revoke the app's consent
immediately if unconfirmed.

## False positive notes
Legitimate SaaS onboarding — users self-service-consenting to real
business tools (Zoom, Slack, Calendly connectors) — is the primary
source of noise. Tune the `highRiskScopes` list to actual risk
tolerance, and maintain an `ApprovedOAuthApps` watchlist for known-good
recurring apps rather than repeatedly re-triaging the same integrations.

## Detection blind spots
`NewUnverifiedApps` only catches apps registered *in this tenant*
(`Add service principal` in `AuditLogs`) — a multi-tenant attacker app
registered in the attacker's own tenant months ago and merely consented
to here for the first time shows no `AppCreatedTime` correlation and
falls into the weaker "Medium - user consent... app age unknown"
tier, even though multi-tenant apps are the more common real-world
illicit-consent-grant pattern. The `highRiskScopes` list is also a
fixed allowlist — a scope not on it (or a newly introduced Graph
permission) produces no signal regardless of how sensitive it actually
is.

## Validation
No confirmed Atomic Red Team test identified — OAuth consent-phishing
isn't a technique ART simulates atomically (it requires a real app
registration and a completed consent flow against a live tenant, not a
local host action). Validate manually: register a test app in a lab
tenant requesting a high-risk scope, consent to it as a test user
within 3 days of registration, and confirm the rule scores it Critical.

## References
- MITRE ATT&CK: [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token)
