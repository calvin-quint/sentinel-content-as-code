---
id: new-azure-vnet-created
title: New Azure Virtual Network Created
tactic: Defense Evasion, Persistence
technique: T1578
sub_technique_name: Modify Cloud Compute Infrastructure
severity: medium
confidence: medium
status: production
platforms:
- sentinel
data_sources:
- AzureActivity
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
  id: 12431f0b-3f10-4edd-8492-a6a38ebbb6ba
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
  - DefenseEvasion
  - Persistence
  relevantTechniques:
  - T1578
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: Name
      columnName: AccountName
    - identifier: UPNSuffix
      columnName: AccountUPNSuffix
  - entityType: IP
    fieldMappings:
    - identifier: Address
      columnName: CallerIpAddress
---

# New Azure Virtual Network Created

## Summary
Flags first-seen creation of a new Azure virtual network, keyed by VNet
name and caller. Attacker-controlled or unsanctioned VNets are often
stood up to isolate staging infrastructure or open network paths that
bypass existing segmentation — review against known change requests.

## Hypothesis
Network topology changes are infrequent and high-impact compared to
routine resource provisioning — a new VNet almost always corresponds to
a deliberate architecture change with a paper trail. A first-seen
`(VnetName, Caller)` pair from an account outside the small set that
normally manages network infrastructure is worth reviewing on that basis
alone.

## Threat intelligence context
No named actor, malware family, or campaign — generic cloud-
infrastructure-abuse detection.

## Query

**Sentinel**
```kusto
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/VIRTUALNETWORKS/WRITE"
| where ActivityStatusValue == "Success"
| where Caller has "@"
| extend VnetName           = tostring(parse_json(Properties).resource)
| extend ResourceGroup    = tostring(parse_json(Properties).resourceGroup)
| extend AccountName      = tostring(split(Caller, "@")[0])
| extend AccountUPNSuffix = tostring(split(Caller, "@")[1])
| summarize arg_min(TimeGenerated, *) by VnetName, Caller
| project
    TimeGenerated,
    AccountName,
    AccountUPNSuffix,
    Caller,
    VnetName,
    ResourceGroup,
    SubscriptionId,
    CallerIpAddress
| sort by TimeGenerated desc
```
(No Defender XDR variant — `AzureActivity` is a Sentinel/Azure Monitor
table with no Defender XDR portal equivalent.)

## What a hit looks like
A `Caller` outside the small group that normally manages network
infrastructure, or a `ResourceGroup`/`VnetName` that doesn't match
existing naming conventions. Cross-reference against open change
requests before escalating.

## False positive notes
IaC pipelines and network engineers doing legitimate topology work will
appear here. Like the VM-creation sibling rule, this is only useful once
known-good callers are handled separately from ad-hoc/interactive
creation.

## Detection blind spots
Keyed on `(VnetName, Caller)` — a compromised account that has
previously created VNets, or an attacker reusing a VNet name, produces
no first-seen signal. Only fires on direct `WRITE` operations against
the ARM resource provider; VNet creation through a nested template or a
different deployment path may not match the expected `Properties` shape.

## Validation
No confirmed Atomic Red Team test identified for this specific technique/
platform pairing. Validate manually: create a test VNet in a
non-production subscription from an account not normally used for
network provisioning, and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/azure-infrastructure/new_azure_vnet_created.kql
- MITRE ATT&CK: [T1578](https://attack.mitre.org/techniques/T1578/) (Modify Cloud Compute Infrastructure)
