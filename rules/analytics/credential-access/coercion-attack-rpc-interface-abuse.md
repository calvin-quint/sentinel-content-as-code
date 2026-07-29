---
id: coercion-attack-rpc-interface-abuse
title: Coercion Attack Detected - Abused RPC Interface (PetitPotam/PrinterBug/ShadowCoerce/DFSCoerce/WSPCoerce)
tactic: Credential Access
technique: T1187
sub_technique_name: Forced Authentication
severity: high
confidence: medium
status: production
platforms: [defender_xdr, sentinel]
data_sources: [DeviceEvents]
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
  id: 8b54b55e-14f4-4c31-b51d-98ae506dd036
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
  relevantTechniques: [T1187]
  entityMappings:
    - entityType: Host
      fieldMappings:
        - identifier: Name
          columnName: DeviceName
    - entityType: IP
      fieldMappings:
        - identifier: Address
          columnName: RemoteIP
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

# Coercion Attack Detected - Abused RPC Interface (PetitPotam/PrinterBug/ShadowCoerce/DFSCoerce/WSPCoerce)

## Summary
Detects inbound RPC calls to any of the five RPC interfaces abused by
the current family of NTLM-coercion techniques — PetitPotam (MS-EFSR),
PrinterBug/SpoolSample (MS-RPRN), ShadowCoerce (MS-FSRVP), DFSCoerce
(MS-DFSNM), and WSPCoerce (MS-WSP) — in one query, detected at the RPC
interface layer rather than by tool signature or process name.

## Hypothesis
Coercion tool names and binaries churn constantly — the PetitPotam PoC
alone has been reimplemented as a NetExec module, Coercer, SharpCoercer,
and multiple bespoke droppers (this repo's own IR-2026-004 incident used
a repurposed clipboard-utility binary, `Ditto.exe`, as the delivery
vehicle, not a purpose-built coercion tool). What doesn't change is the
underlying RPC interface each technique has to call to force
authentication. Detecting at that layer catches the technique
regardless of which tool or wrapper fired it, including tools that
don't exist yet.

## Threat intelligence context
No named actor, malware family, or campaign tied to this rule directly —
it targets the general forced-authentication technique class. IR-2026-004
(this repo's own incident) confirmed live use of this pattern: 10 distinct
MS-EFSR methods called against a domain-joined workstation in a 2-minute
window, consistent with a PetitPotam-style PoC cycling through methods
individual patch levels block one at a time, delivered via a malicious
MSI masquerading as a clipboard utility rather than a dedicated coercion
binary.

## Query

**Sentinel / Defender XDR**
```kusto
let lookback = 1d;
let CoercionInterfaces = dynamic([
    "EncryptingFileSystem",   // MS-EFSR   - PetitPotam
    "PrintSystemRemote",      // MS-RPRN   - PrinterBug / SpoolSample
    "FileServerVssAgent",     // MS-FSRVP  - ShadowCoerce
    "DfsNamespaceManagement", // MS-DFSNM  - DFSCoerce
    "WindowsSearchProtocol"   // MS-WSP    - WSPCoerce (workstations - wsearch enabled by default)
]);
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundRemoteRpcCall"
| extend AF = parse_json(AdditionalFields)
| extend RpcInterfaceName = tostring(AF.RpcInterfaceName),
         RpcOperationName = tostring(AF.RpcOperationName),
         RemoteIP = tostring(AF.RemoteIP)
| where RpcInterfaceName in (CoercionInterfaces)
| summarize
    DistinctMethodsFired = dcount(RpcOperationName),
    MethodsSeen          = make_set(RpcOperationName),
    FirstCall             = min(Timestamp),
    LastCall               = max(Timestamp)
  by DeviceName, RemoteIP, RpcInterfaceName, bin(Timestamp, 1h)
| order by DistinctMethodsFired desc, LastCall desc
```
Same query works unchanged in Defender XDR advanced hunting and
Sentinel — `DeviceEvents` is a shared MDE-sourced table in both.

## Analytics rule configuration
| | |
|---|---|
| Frequency / Period | `PT1H` / `P1D` |
| Trigger | `gt 0` |
| Tactics / Techniques | Credential Access — T1187 |
| Entity mappings | `Host.Name = DeviceName` · `IP.Address = RemoteIP` |
| Incident grouping | All entities, 5h lookback |

## What a hit looks like
Any row is worth a first look — these five interfaces have essentially
no benign day-to-day call volume outside of a domain controller talking
to itself or a legitimate EFS/DFS/print/search operation. Prioritize by
`RpcInterfaceName`:
- **EncryptingFileSystem** — weight `DistinctMethodsFired`. A legitimate
  EFS operation calls 1-2 methods; PoC tools (topotam/Kekeo-derived)
  walk nearly the entire MS-EFSR method set because different patch
  levels block individual methods, not the whole interface.
  `DistinctMethodsFired >= 4` in a single hour is a strong signal.
- **PrintSystemRemote / FileServerVssAgent / DfsNamespaceManagement /
  WindowsSearchProtocol** — these are rarer and typically single-call
  techniques (DFSCoerce fires one specific method); don't wait for a
  method-cycling pattern on these four. Any call from a non-DC,
  non-admin, non-backup source is immediately actionable.

Cross-reference `DeviceName` (the target that received the RPC call)
against known Tier-0 assets — a coercion call landing on a domain
controller is the highest-priority combination, since the goal of every
one of these techniques is to force the DC to authenticate to an
attacker-controlled relay.

## False positive notes
Legitimate replication, backup, and file-services traffic exists on
these interfaces (Azure AD Connect, backup product AD-aware agents,
DFS Namespace servers doing real DFS management, Windows Search
crawling network shares from an indexed workstation). Baseline for a
few days per interface and maintain a `KnownGoodSources` allowlist of
IPs/accounts that legitimately call each interface rather than
suppressing an interface outright — the whole point of this rule is
that any *other* source calling these interfaces is abnormal.

## Detection blind spots
Only sees calls to devices actually onboarded to MDE and generating
`DeviceEvents` — a coercion call landing on an unmanaged or legacy
device that doesn't report to Defender produces no signal. This is also
a lagging indicator of the coercion *call*, not the relay or its
outcome — a coerced authentication that gets successfully relayed to
ADCS or used for DCSync requires the companion checks (NTLM Operational
log 8001-8004, or the DCSync detection rule) to confirm impact, since a
coercion call landing is necessary but not sufficient evidence of a
successful attack.

## Validation
No confirmed Atomic Red Team test identified — forced-authentication
coercion techniques require standing up a target RPC listener and a
domain-joined attack path, which most atomic tests don't simulate
directly. Validate manually: run the PetitPotam PoC (or `NetExec`'s
`coerce_plus` module) against a lab domain controller and confirm the
rule fires on `EncryptingFileSystem` with `DistinctMethodsFired >= 4`.

## References
- MITRE ATT&CK: [T1187](https://attack.mitre.org/techniques/T1187/) (Forced Authentication)
- Community coercion-pipe hunting guidance: NCC Group / Fox-IT
