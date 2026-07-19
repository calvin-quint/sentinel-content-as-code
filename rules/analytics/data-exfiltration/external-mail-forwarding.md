---
id: external-mail-forwarding
title: External Mail Forwarding (Non-Org Domain)
tactic: Collection
technique: T1114.003
sub_technique_name: Email Forwarding Rule
severity: high
confidence: high
status: production
platforms:
- sentinel
data_sources:
- OfficeActivity
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
  id: adf2e88f-be62-4c04-baf8-ae88b36e7dbe
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
  - Collection
  relevantTechniques:
  - T1114.003
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: Name/UPNSuffix
      columnName: AccountName/AccountUPNSuffix
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: ClientIPAddress
---

# External Mail Forwarding (Non-Org Domain)

## Summary
Flags mailbox-level forwarding (`Set-Mailbox ForwardingSmtpAddress`) or
inbox-rule forwarding/redirect actions whose destination domain doesn't
match the org's own root domain — the standard post-compromise
persistence step for silently exfiltrating a victim's mail without
needing repeat access to the mailbox.

## Hypothesis
Legitimate mail forwarding to an external domain is rare in most
organizations — forwarding rules pointed outside the org's own root
domain (dynamically derived from the account's own UPN suffix rather
than a hardcoded value, so it handles subdomains correctly) are
uncommon enough to review individually rather than needing anomaly
scoring.

## Threat intelligence context
No named actor, malware family, or campaign — a generic post-compromise
persistence detection.

## Query

**Sentinel**
```kusto
OfficeActivity
| where OfficeWorkload == "Exchange"
| where (Operation == "Set-Mailbox" and Parameters contains "ForwardingSmtpAddress")
    or (Operation in ("New-InboxRule", "Set-InboxRule")
        and (Parameters contains "ForwardTo" or Parameters contains "RedirectTo"))
| extend ParametersJson = parse_json(Parameters)
| mv-expand Param = ParametersJson
| extend paramName  = tostring(Param.Name)
| extend paramValue = tostring(Param.Value)
| where paramName in ("ForwardingSmtpAddress", "ForwardTo", "RedirectTo", "ForwardingAddress")
| where isnotempty(paramValue)
| mv-expand fwdingDestination = split(paramValue, ";")
| extend fwdingDestination = trim(" ", tostring(fwdingDestination))
| extend fwdingDestination = iff(fwdingDestination has "smtp:", split(fwdingDestination, ":")[1], fwdingDestination)
| where isnotempty(fwdingDestination)
| parse fwdingDestination with * "@" ForwardedtoDomain
| where isnotempty(ForwardedtoDomain)
| extend AccountUPNSuffix = tostring(split(UserId, "@")[1])
// Derive the org's root domain (last two labels) to handle subdomains
| extend OrgRootDomain = strcat(
    tostring(split(AccountUPNSuffix, ".")[-2]), ".",
    tostring(split(AccountUPNSuffix, ".")[-1])
  )
| where ForwardedtoDomain !endswith OrgRootDomain
| extend RuleName    = extract(@'"Name":"Name","Value":"([^"]+)"', 1, Parameters)
| extend RuleEnabled = extract(@'"Name":"Enabled","Value":"?([^",}]+)"?', 1, Parameters)
| extend ClientIPAddress = case(
    ClientIP has "." and ClientIP has ":", tostring(split(ClientIP, ":")[0]),
    ClientIP has "[",                      trim_start(@"\[", tostring(split(ClientIP, "]")[0])),
    ClientIP)
| extend Port = case(
    ClientIP has "." and ClientIP has ":", tostring(split(ClientIP, ":")[1]),
    ClientIP has "[",                      tostring(split(ClientIP, "]:")[1]),
    "")
| extend AccountName = tostring(split(UserId, "@")[0])
| project
    TimeGenerated,
    AccountName,
    AccountUPNSuffix,
    Operation,
    RuleName,
    RuleEnabled,
    fwdingDestination,
    ForwardedtoDomain,
    OrgRootDomain,
    ClientIPAddress,
    Port,
    OriginatingServer,
    OfficeObjectId
| sort by TimeGenerated desc
```
(No Defender XDR variant — `OfficeActivity` is a Sentinel/M365 audit
table with no Defender XDR portal equivalent.)

## What a hit looks like
An `AccountName` with a `ForwardedtoDomain` that doesn't match
`OrgRootDomain`. Cross-reference `ClientIPAddress` against the account's
normal sign-in pattern and confirm with the user whether the forward
was intentional.

## False positive notes
Legitimate business needs (a user forwarding to a personal secondary
account with IT approval, a contractor with an external domain) can
produce genuine hits. This is intentionally broad — the narrower
[`mail_forwarding_to_free_email_provider.md`](mail_forwarding_to_free_email_provider.md)
rule exists specifically to isolate the higher-confidence subset
(forwarding to known consumer webmail).

## Detection blind spots
Only catches forwarding configured through `Set-Mailbox` or inbox rules
via the tracked parameter names — a forwarding mechanism outside those
(e.g., a mail flow/transport rule, covered separately in
[`transport_rule_redirects.md`](transport_rule_redirects.md)) isn't
covered here. The root-domain derivation assumes a standard two-label
TLD structure (`example.com`); a UPN suffix using a multi-part public
suffix (e.g., `example.co.uk`) would be miscalculated as `co.uk`,
producing incorrect `OrgRootDomain` comparisons for those tenants.

## Validation
No confirmed Atomic Red Team test identified — Exchange mail-forwarding
configuration isn't a technique ART simulates directly (closest coverage
is generic T1114 email-collection atomics, not this specific
configuration action). Validate manually: configure external forwarding
on a test mailbox in a lab tenant and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/external_mail_forwarding.kql
- MITRE ATT&CK: [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Forwarding Rule)
