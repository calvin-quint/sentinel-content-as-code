---
id: transport-rule-redirects
title: Transport Rule BCC/Redirect Created or Modified
tactic: Collection
technique: T1114.003
sub_technique_name: Email Forwarding Rule
severity: critical
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
  id: 557b06ce-187f-46d9-99fc-057c0f968932
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
      columnName: Account_0_Name/Account_0_UPNSuffix
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: IP_0_Address
---

# Transport Rule BCC/Redirect Created or Modified

## Summary
Flags org-wide Exchange transport rule creation/modification that adds
a `BlindCopyTo` or `RedirectMessageTo` action. Transport rules apply at
the tenant mail-flow level rather than a single mailbox, so a malicious
or compromised-admin rule here silently BCCs or redirects mail across
many/all users at once — a far larger blast radius than a personal
inbox rule, and typically requires Exchange admin privileges to create.

## Hypothesis
Transport-rule-level BCC/redirect actions require elevated Exchange
admin privileges and affect mail flow tenant-wide, unlike a personal
inbox rule. Given both the privilege required and the blast radius,
essentially every instance of this action warrants same-day review
regardless of who created it — this isn't a behavior to baseline, it's
a rare, high-impact administrative action.

## Threat intelligence context
No named actor, malware family, or campaign — a generic detection for
a high-blast-radius admin-level persistence/collection mechanism.

## Query

**Sentinel**
```kusto
OfficeActivity
  | where OfficeWorkload == "Exchange"
  | where Operation in~ ("New-TransportRule", "Set-TransportRule")
  | mv-apply DynamicParameters = todynamic(Parameters) on (summarize ParsedParameters = make_bag(pack(tostring(DynamicParameters.Name), DynamicParameters.Value)))
  | extend RuleName = case(
      Operation =~ "Set-TransportRule", OfficeObjectId,
      Operation =~ "New-TransportRule", ParsedParameters.Name,
      "Unknown")
  | mv-expand ExpandedParameters = todynamic(Parameters)
  | where ExpandedParameters.Name in~ ("BlindCopyTo", "RedirectMessageTo") and isnotempty(ExpandedParameters.Value)
  | extend RedirectTo = ExpandedParameters.Value
  | extend ClientIPValues = extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.\d+\.\d+)|[^\]]+)\]?([-:](?P<Port>\d+))?', dynamic(["IPAddress", "Port"]), ClientIP)[0]
  | project TimeGenerated, RedirectTo, IPAddress = tostring(ClientIPValues[0]), Port = tostring(ClientIPValues[1]), UserId, Operation, RuleName, Parameters
  | extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix = tostring(split(UserId, "@")[1])
  | extend Account_0_Name = AccountName
  | extend Account_0_UPNSuffix = AccountUPNSuffix
  | extend IP_0_Address = IPAddress
```
(No Defender XDR variant — `OfficeActivity` is a Sentinel/M365 audit
table with no Defender XDR portal equivalent.)

## What a hit looks like
Any row is significant. Identify `UserId` (the admin who made the
change), `RuleName`, and `RedirectTo`/BCC destination, and confirm
against a documented change request before treating it as legitimate.

## False positive notes
Legitimate compliance/archiving transport rules (e.g., BCC to a
regulatory archive mailbox) exist in many orgs and will match this rule
by design. These should be pre-documented as known-good, reviewed
periodically for drift, not silently excluded — a legitimate archive
rule quietly modified to add an additional unauthorized recipient would
otherwise go unnoticed.

## Detection blind spots
Only catches `BlindCopyTo`/`RedirectMessageTo` actions specifically — a
transport rule using a different action to achieve a similar effect
(e.g., a forwarding action via a different parameter name, or a rule
that modifies content/routing without a copy/redirect action) isn't
covered. Requires Exchange admin audit logging to be enabled and
retained; if transport-rule changes aren't being logged for any reason,
this rule sees nothing.

## Validation
No confirmed Atomic Red Team test identified — Exchange transport-rule
configuration isn't a technique ART simulates. Validate manually: create
a test transport rule with a `BlindCopyTo` action in a lab tenant and
confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/data-exfiltration/transport_rule_redirects.kql
- MITRE ATT&CK: [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Forwarding Rule)
