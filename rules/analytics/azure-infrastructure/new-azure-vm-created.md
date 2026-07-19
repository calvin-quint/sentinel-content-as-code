---
id: new-azure-vm-created
title: New Azure VM Created
tactic: Defense Evasion, Persistence
technique: T1578.002
sub_technique_name: Modify Cloud Compute Infrastructure - Create Cloud Instance
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
  id: 57a718e9-bd1e-4205-97d3-5facea60b2a9
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
  - T1578.002
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

# New Azure VM Created

## Summary
Flags first-seen creation of a new Azure virtual machine, keyed by VM
name and caller. A compromised account or malicious insider can spin up
a VM for crypto-mining, C2 relay, or a staging box outside normal
change-management — new or unexpected callers/resource groups are the
signal to chase.

## Hypothesis
VM creation in a managed Azure environment should map to known change
requests and a small, stable set of callers (IaC pipelines, a handful of
platform engineers). A first-seen `(VMName, Caller)` pair — especially
from an account that doesn't normally provision infrastructure — is
worth reviewing regardless of whether the subscription has budget
alerts or resource locks, since those don't stop unauthorized creation,
only flag cost after the fact.

## Threat intelligence context
No named actor, malware family, or campaign — generic cloud-
infrastructure-abuse detection.

## Query

**Sentinel**
```kusto
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE"
| where ActivityStatusValue == "Success"
| where Caller has "@"
| extend VMName           = tostring(parse_json(Properties).resource)
| extend ResourceGroup    = tostring(parse_json(Properties).resourceGroup)
| extend AccountName      = tostring(split(Caller, "@")[0])
| extend AccountUPNSuffix = tostring(split(Caller, "@")[1])
| summarize arg_min(TimeGenerated, *) by VMName, Caller
| project
    TimeGenerated,
    AccountName,
    AccountUPNSuffix,
    Caller,
    VMName,
    ResourceGroup,
    SubscriptionId,
    CallerIpAddress
| sort by TimeGenerated desc
```
(No Defender XDR variant — `AzureActivity` is a Sentinel/Azure Monitor
table with no Defender XDR portal equivalent.)

## What a hit looks like
A `Caller` who doesn't normally provision infrastructure, or a
`ResourceGroup` outside the org's normal naming/change-management
pattern. Cross-reference `CallerIpAddress` against the account's usual
sign-in geography.

## False positive notes
Legitimate IaC pipelines (Terraform/Bicep service principals) and
platform engineers provisioning VMs as part of normal work will appear
here constantly. This rule is only useful once known-good callers are
either excluded or handled separately from ad-hoc/interactive creation —
as written, every VM creation fires once per `(VMName, Caller)` pair,
so noise scales with how much legitimate provisioning the org does.

## Detection blind spots
Keyed on `(VMName, Caller)` — an attacker who reuses a previously-seen VM
name, or a compromised account that has provisioned VMs before, produces
no "first-seen" signal. Only fires on successful `WRITE` operations
against the ARM resource provider directly; VM creation through a
different path (e.g., a marketplace deployment template or a nested ARM
template) may not surface with the same `Properties` shape this query
expects.

## Validation
No confirmed Atomic Red Team test identified for this specific technique/
platform pairing (Azure VM creation under T1578.002) — Atomic Red Team's
cloud-platform atomics cover related cloud infrastructure techniques but
a verified match wasn't found for this one. Validate manually: create a
test VM in a non-production subscription from an account not normally
used for provisioning, and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/azure-infrastructure/new_azure_vm_created.kql
- MITRE ATT&CK: [T1578.002](https://attack.mitre.org/techniques/T1578/002/) (Modify Cloud Compute Infrastructure: Create Cloud Instance)
