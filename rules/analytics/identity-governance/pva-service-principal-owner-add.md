---
id: pva-service-principal-owner-add
title: Power Virtual Agents Adding Service Principal Owner
tactic: Persistence, Privilege Escalation
technique: T1098.003
sub_technique_name: Account Manipulation - Additional Cloud Roles
severity: high
confidence: high
status: production
platforms:
- sentinel
data_sources:
- AuditLogs
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
  id: 9dc086d2-c0e7-4b6b-8e95-19171b6a4d5a
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
  - Persistence
  - PrivilegeEscalation
  relevantTechniques:
  - T1098.003
  entityMappings:
  - entityType: Account
    fieldMappings:
    - identifier: UPN
      columnName: userPrincipalName
---

# Power Virtual Agents Adding Service Principal Owner

## Summary
Flags a service principal ownership change initiated by Power Virtual
Agents specifically — an unusual actor for this operation. Owning a
service principal grants control over its credentials and permissions,
so a Power Platform bot/flow granting itself or another principal
ownership is a plausible privilege-escalation path via low-code
automation that's easy to overlook.

## Hypothesis
Service principal ownership changes initiated by Power Virtual Agents
have essentially no legitimate use case — this is a low-code automation
product, not an identity-administration tool, so it should never be the
`InitiatedBy` actor for an "Add owner to service principal" operation.
Any occurrence is either a misconfigured flow being abused as an
unintended privilege-escalation path, or a deliberately malicious flow
built specifically for that purpose.

## Threat intelligence context
No named actor, malware family, or campaign — a low-code-automation
privilege-escalation pattern, not threat-intel-driven.

## Query

**Sentinel**
```kusto
AuditLogs
| where OperationName contains "Add owner to service principal"
| where tostring(InitiatedBy) contains "Power Virtual Agents"
| mv-expand TargetResources
| extend userPrincipalName = tostring(TargetResources.userPrincipalName)
```
(No Defender XDR variant — `AuditLogs` is a Sentinel/Entra ID table with
no Defender XDR portal equivalent.)

## What a hit looks like
Any row at all is significant — identify which service principal
received a new owner, which flow/bot initiated it, and who built or has
edit access to that Power Virtual Agents flow.

## False positive notes
None expected under normal operation — this pairing of actor and
operation has no known legitimate business use. If a genuine automated
provisioning workflow is later built that relies on this pattern, it
should be explicitly documented and excluded by flow ID, not by loosening
this rule generally.

## Detection blind spots
Only catches Power Virtual Agents specifically as the initiating actor —
the same privilege-escalation path via a different Power Platform
product (Power Automate, Power Apps) or any other low-code/no-code
automation tool wouldn't match this rule's `InitiatedBy` string check.
Broadening it to other Power Platform products is a natural next
iteration if similar abuse is seen elsewhere.

## Validation
No confirmed Atomic Red Team test identified — this is a specific
low-code-platform privilege-escalation path ART doesn't model. Validate
manually: build a test Power Virtual Agents flow that adds an owner to a
service principal in a lab tenant and confirm the rule fires.

## References
- Original source: https://github.com/calvin-quint/docs/blob/main/01-detection-engineering/kql/identity-governance/pva_service_principal_owner_add.kql
- MITRE ATT&CK: [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation: Additional Cloud Roles)
