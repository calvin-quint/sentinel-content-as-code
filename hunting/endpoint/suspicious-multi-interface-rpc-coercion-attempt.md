---
id: "suspicious-multi-interface-rpc-coercion-attempt"
title: "Suspicious Multi-Interface RPC Coercion Attempt"
tactic: "Credential Access, Lateral Movement"
technique: "T1187, T1021"
sub_technique_name: ""
severity: "high"
confidence: "high"
status: draft
platforms: [defender_xdr]
data_sources: [DeviceEvents]
sigma_source: null
threat_intel:
  family: null
  actor: null
  campaign: null
  first_seen: null
  references: []
  yara_rule: null
validated:
  atomic_test: null
  atomic_test_url: null
  lab_ref: null
  last_run: null
  result: null
owner: "Calvin Quint"
last_reviewed: "2026-08-05"
---

# Suspicious Multi-Interface RPC Coercion Attempt

## Summary
Detects bursts of distinct RPC methods called from the same remote IP against interfaces commonly abused by PetitPotam, Coercer, PrinterBug/SpoolSample, ShadowCoerce, and DFSCoerce. Interface-specific thresholds highlight automated attempts to force a Windows host to authenticate to attacker-controlled infrastructure.

## Hypothesis
Normal remote administration rarely invokes several distinct operations against coercion-abusable RPC interfaces from one source within five minutes. A threshold-crossing burst is more likely to represent automated NTLM coercion discovery or exploitation.

## Threat intelligence context
This behavior is associated with multiple public NTLM coercion techniques and tools rather than one malware family or actor. Coercion tooling abuses exposed RPC methods to make a target authenticate to another system, enabling credential relay or capture when surrounding controls permit it.

## Query

**Defender XDR**
```kusto
// Keep the 30-day Timestamp filter for standalone hunting/testing.
// Remove it before converting this hunt to a scheduled analytics rule.
let InterfaceThresholds = datatable(RpcInterface: string, MethodThreshold: int)
[
    "EncryptingFileSystem", 3,
    "MS-RPRN",              2,
    "MS-FSRVP",             2,
    "MS-DFSNM",             2,
    "MS-EVEN",              2,
    "MS-EVEN6",             2,
    "MS-DSSP",              1
];
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "InboundRemoteRpcCall"
| extend AdditionalFieldsParsed = parse_json(AdditionalFields)
| extend RpcInterface = tostring(AdditionalFieldsParsed.RpcInterfaceName)
| where RpcInterface in ((InterfaceThresholds | project RpcInterface))
| extend RpcOperationName = tostring(AdditionalFieldsParsed.RpcOperationName)
| summarize DistinctMethods = dcount(RpcOperationName),
            MethodsSeen = make_set(RpcOperationName),
            FirstCall = min(Timestamp), LastCall = max(Timestamp)
    by DeviceName, RemoteIP, RpcInterface, bin(Timestamp, 5m)
| join kind=inner InterfaceThresholds on RpcInterface
| where DistinctMethods >= MethodThreshold
| project DeviceName, RemoteIP, RpcInterface, DistinctMethods, MethodThreshold, MethodsSeen, FirstCall, LastCall
| order by DistinctMethods desc
```

## What a hit looks like
A result identifies the targeted device, remote source IP, abused RPC interface, configured threshold, number of distinct operations, operation names, and the first and last calls in the five-minute bucket. Multiple interfaces or devices tied to one source strengthen the case for automated coercion activity.

## False positive notes
Vulnerability scanners, RPC compatibility testing, backup software, print administration, and legitimate management tools may exercise several methods rapidly. Validate whether the source is an approved scanner or management server, review authentication traffic immediately following the calls, and check whether the destination attempted SMB or HTTP authentication to a new system.

## Detection blind spots
Coverage depends on Defender emitting `InboundRemoteRpcCall` with populated interface and operation names. Single-method attacks below the configured threshold, coercion through unlisted interfaces, activity spread across five-minute buckets, and telemetry-disabled devices may evade the hunt. The query groups by interface, so a tool that calls one method on several different interfaces may not cross any per-interface threshold.

## Validation
This hunt has not yet been validated against a live Coercer-family simulation. Test each listed RPC interface from a controlled remote host, confirm the interface names in `AdditionalFields`, verify threshold behavior, and correlate resulting outbound authentication before promotion beyond draft.

## References
- [MITRE ATT&CK T1187: Forced Authentication](https://attack.mitre.org/techniques/T1187/)
- [MITRE ATT&CK T1021: Remote Services](https://attack.mitre.org/techniques/T1021/)
- [Microsoft: Mitigating NTLM relay attacks by default](https://support.microsoft.com/topic/mitigating-ntlm-relay-attacks-by-default-11ba700a-5b03-46d6-a980-2a08abf73f6e)


