---
id: mail-forwarding-to-free-email-provider
title: Mail Forwarding to Free/Personal Email Provider
tactic: Collection, Exfiltration
technique: T1114.003, T1567
sub_technique_name: Email Forwarding Rule / Exfiltration Over Web Service
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
  id: 75ebeacf-725e-4131-9964-f22e94cefbd7
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
  - Exfiltration
  relevantTechniques:
  - T1114.003
  - T1567
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

# Mail Forwarding to Free/Personal Email Provider

## Summary
Narrower, higher-confidence sibling of
[`external_mail_forwarding.md`](external_mail_forwarding.md) — flags
mailbox forwarding or inbox-rule redirects whose destination domain
matches a known consumer webmail provider (Gmail, Yahoo, Outlook.com,
iCloud, ProtonMail, etc.). Forwarding to a personal inbox has essentially
no legitimate business reason and is a common self-exfiltration or
departing-employee pattern.

## Hypothesis
Unlike forwarding to an arbitrary external domain (which could be a
legitimate business partner), forwarding specifically to a named
consumer webmail provider has almost no business justification. Matching
against a fixed list of known personal-email domains turns a broad,
lower-confidence signal into a narrow, high-confidence one.

## Threat intelligence context
No named actor, malware family, or campaign — targets the general
pattern of self-exfiltration to personal accounts, common in departing-
employee and insider-risk scenarios rather than a specific threat actor.

## Query

**Sentinel**
```kusto
let PersonalDomains = datatable(domain:string)[
    "gmail.com", "googlemail.com",
    "yahoo.com", "ymail.com", "yahoo.co.uk",
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "aol.com",
    "zoho.com",
    "gmx.com", "gmx.net",
    "mail.com"
];
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
| join kind=inner PersonalDomains on $left.ForwardedtoDomain == $right.domain
| extend RuleName   = extract(@'"Name":"Name","Value":"([^"]+)"', 1, Parameters)
| extend RuleEnabled = extract(@'"Name":"Enabled","Value":"?([^",}]+)"?', 1, Parameters)
| extend ClientIPAddress = case(
    ClientIP has "." and ClientIP has ":", tostring(split(ClientIP, ":")[0]),
    ClientIP has "[",                      trim_start(@"\[", tostring(split(ClientIP, "]")[0])),
    ClientIP)
| extend Port = case(
    ClientIP has "." and ClientIP has ":", tostring(split(ClientIP, ":")[1]),
    ClientIP has "[",                      tostring(split(ClientIP, "]:")[1]),
    "")
| extend AccountName      = tostring(split(UserId, "@")[0])
| extend AccountUPNSuffix = tostring(split(UserId, "@")[1])
| project
    TimeGenerated,
    AccountName,
    AccountUPNSuffix,
    Operation,
    RuleName,
    RuleEnabled,
    fwdingDestination,
    ForwardedtoDomain,
    ClientIPAddress,
    Port,
    OriginatingServer,
    OfficeObjectId
| sort by TimeGenerated desc
```
(No Defender XDR variant — `OfficeActivity` is a Sentinel/M365 audit
table with no Defender XDR portal equivalent.)

## What a hit looks like
Any hit here warrants same-day review — an `AccountName` forwarding to a
domain on the `PersonalDomains` list. Confirm with HR/manager whether
this is a departing employee or an active insider-risk case.

## False positive notes
Rare legitimate exceptions exist (an executive personally using Gmail
for scheduling with an assistant's knowledge, for example) but should be
formally documented exceptions, not routine — treat every hit as
requiring a specific business justification, not assume benign intent.

## Detection blind spots
Only matches the fixed `PersonalDomains` list — a personal domain not on
the list (a smaller or regional webmail provider, or a custom domain the
user personally owns) evades this rule entirely and would only be
caught by the broader `external_mail_forwarding.md` rule instead.

## Validation
No confirmed Atomic Red Team test identified — Exchange mail-forwarding
configuration to a specific provider isn't a technique ART simulates.
Validate manually: configure forwarding to a Gmail/Yahoo test address on
a test mailbox in a lab tenant and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/mail_forwarding_to_free_email_provider.kql
- MITRE ATT&CK: [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Forwarding Rule), [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service)
