---
id: dcsync-replication-request
title: DCSync - Directory Replication Request From a Non-DC Principal
tactic: Credential Access
technique: T1003.006
sub_technique_name: OS Credential Dumping - DCSync
severity: high
confidence: high
status: production
platforms: [sentinel]
data_sources: [SecurityEvent]
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
  id: b1f66aa4-28f0-498c-9288-9bb68fe942be
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
  relevantTechniques: [T1003.006]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: Computer
    - entityType: Account
      fieldMappings:
        - identifier: Name
          columnName: SubjectUserName
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
last_reviewed: "2026-07-29"
---

# DCSync - Directory Replication Request From a Non-DC Principal

## Summary
Detects a DCSync attack — abuse of MS-DRSR (Directory Replication
Service Remote Protocol) via `GetNCChanges` to request password hash
replication as if the requestor were a domain controller — confirms
full domain compromise when it fires from anything other than a known
DC or an already-baselined replication account.

## Hypothesis
Only domain controllers, and a small, known set of replication-capable
service accounts (Azure AD Connect's `MSOL_` sync account, AD-aware
backup agents, identity-governance tooling), should ever exercise the
`DS-Replication-Get-Changes[-All]` extended rights. A request for those
rights from any other principal — especially a non-machine account — has
essentially no legitimate explanation and represents an attacker who has
already obtained (or coerced) sufficient privilege to request a full
directory replication, which is one step away from extracting every
credential in the domain, including the krbtgt hash needed for a Golden
Ticket.

## Threat intelligence context
No named actor, malware family, or campaign tied to this rule directly —
DCSync is a generic post-compromise technique used across ransomware,
APT, and red-team tooling alike once Tier-0 access is reached. This
version is corrected against a real incident (IR-2026-004): an earlier
draft of this same query incorrectly scoped `hqdc03` into `KnownDCs`,
which would have suppressed a real hit if `hqdc03` itself had been the
compromised replication source — confirmed via investigation that only
`hqdc01`, `hqdc02`, `opclddc01`, and `opclddc02` actually hold
replication rights in this environment. If deploying this in a
different environment, re-derive `KnownDCs` from that environment's own
domain controller list rather than reusing this one's.

## Query

**Sentinel**
```kusto
let ReplicationGUIDs = dynamic([
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes-All
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes
    "89e95b76-444d-4c62-991a-0facbeda640c"   // DS-Replication-Get-Changes-In-Filtered-Set
]);
let KnownDCs = dynamic(["HQDC01$", "HQDC02$", "OPCLDDC01$", "OPCLDDC02$"]);  // re-derive per environment
let KnownReplicationAccounts = dynamic([]);  // populate after baselining: MSOL_ sync account, backup product AD-aware agents, identity governance tooling
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4662
| where Properties has_any (ReplicationGUIDs)
| where SubjectUserName !in (KnownDCs)
    and SubjectUserName !in (KnownReplicationAccounts)
| extend
    Flag_NonDC = iff(SubjectUserName !endswith "$", "[NON_MACHINE_ACCOUNT] ", ""),
    MatchedGUID = case(
        Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-All",
        Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes",
        Properties has "89e95b76-444d-4c62-991a-0facbeda640c", "DS-Replication-Get-Changes-In-Filtered-Set",
        "Unknown"
    )
| project
    TimeGenerated,
    Computer,
    EventType = strcat(Flag_NonDC, "[DCSYNC_SUSPECTED]"),
    SubjectUserName,
    SubjectUserSid,
    ObjectName,
    MatchedGUID,
    Properties,
    LogonId
| order by TimeGenerated asc
```
(No Defender XDR variant — `SecurityEvent` Event ID 4662 requires the
Windows Security Events connector (AMA/legacy agent) with "Audit
Directory Service Access" enabled on the DCs; not available via
Defender XDR advanced hunting.)

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Credential Access — T1003.006 |
| Entity mappings | `Host.Name = Computer` · `Account.Name = SubjectUserName` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
Any row is a near-certain positive once the audit policy is confirmed
enabled and `KnownReplicationAccounts` is properly baselined —
`EventType` prefixed `[NON_MACHINE_ACCOUNT]` (a user account, not a
computer account, requesting replication rights) is the highest-priority
variant, since real replication sources are almost always machine
accounts. Pivot immediately to `LogonId` against Event 4624 on the same
DC to pull the actual source IP the request came from — a bare 4662
doesn't include it.

## False positive notes
Expect noise on first run. Legitimate replication sources not yet in
`KnownReplicationAccounts` — other DCs not yet added to `KnownDCs`,
Azure AD Connect's `MSOL_` sync account, backup product AD-aware
agents, identity-governance tooling — will also hit these GUIDs.
Baseline for a few days, populate `KnownReplicationAccounts`, then
treat anything left as a real hit.

## Detection blind spots
If "Audit Directory Service Access" isn't enabled on the DCs, this
query silently returns nothing — that is an unmeasured result, not a
clean one, the same trap as the NTLM Operational log and DFS Namespace
event checks this rule's companion coercion detection depends on. No
alternate detection path exists for DCSync if this audit policy isn't
on: DCSync never touches LSASS or runs code on the DC itself, so
process/memory-based EDR telemetry won't see it either.

## Validation
No confirmed Atomic Red Team test identified that exercises DCSync
against a live DC without actually compromising one — most safe
simulations use `secretsdump.py -just-dc-user` or Mimikatz's
`lsadump::dcsync` against a disposable lab domain. Validate manually:
grant a disposable test account replication rights in a lab domain, run
`secretsdump.py <domain>/<test-account>@<dc> -just-dc-user
krbtgt`, and confirm the rule fires with `EventType` correctly flagged
`[NON_MACHINE_ACCOUNT]`.

## References
- MITRE ATT&CK: [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)
