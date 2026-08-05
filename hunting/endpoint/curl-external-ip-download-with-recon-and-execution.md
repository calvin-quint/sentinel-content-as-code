---
id: "curl-external-ip-download-with-recon-and-execution"
title: "Curl External IP Download with Reconnaissance and Execution"
tactic: "Command and Control, Discovery, Execution"
technique: "T1105, T1082, T1016, T1046"
sub_technique_name: ""
severity: "medium"
confidence: "medium"
status: draft
platforms: [defender_xdr]
data_sources: [DeviceProcessEvents]
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

# Curl External IP Download with Reconnaissance and Execution

## Summary
Identifies `curl` downloading from an external IPv4 literal and enriches the event with nearby command-shell reconnaissance and follow-on execution through commonly abused Windows binaries. IP-literal downloads combined with discovery or rapid execution can indicate staged payload delivery that avoids domain-based controls and telemetry.

## Hypothesis
Legitimate Windows software distribution usually uses named, trusted domains or managed deployment tooling. A direct external-IP download with `curl`, especially when preceded by command-shell reconnaissance or followed quickly by a script interpreter or proxy-execution binary, is more likely to represent hands-on-keyboard intrusion activity.

## Threat intelligence context
This is a behavior-based hunt with no specific named malware family, threat actor, or campaign attribution. It covers a general ingress-tool-transfer pattern in which an operator downloads content from an external IP literal, potentially after host or network discovery, and then executes the retrieved content through a commonly abused Windows binary.

## Query

**Defender XDR**
```kusto
let ReconCommands = dynamic(["systeminfo.exe", "ipconfig.exe", "nslookup.exe", "ping.exe", "net.exe", "net1.exe"]);
let ExecAfterDownload = dynamic(["msiexec.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "wscript.exe", "powershell.exe"]);
let PrivateIPRegex = @"(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)";
let Downloads =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("curl.exe", "curl")
    | where ProcessCommandLine matches regex @"https?:\/\/(\d{1,3}\.){3}\d{1,3}"
    | where not(ProcessCommandLine matches regex PrivateIPRegex)
    | extend HasInsecureOrSilent = ProcessCommandLine has_any ("-k", "--insecure", "-s ", "--silent")
    | extend DownloadTime = Timestamp
    | project DownloadTime, DeviceName, AccountName, ProcessCommandLine, ParentProcess = InitiatingProcessFileName, HasInsecureOrSilent;
let ExecEvents =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (ExecAfterDownload)
    | project ExecTimestamp = Timestamp, DeviceName, ExecFileName = FileName;
let ReconEvents =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (ReconCommands)
    | where tolower(InitiatingProcessFileName) == "cmd.exe"
    | project ReconTimestamp = Timestamp, DeviceName, ReconCommand = FileName;
let MatchedExec =
    Downloads
    | join kind=inner (ExecEvents) on DeviceName
    | where ExecTimestamp between (DownloadTime .. DownloadTime + 10m)
    | summarize ExecFileNames = make_set(ExecFileName, 5) by DownloadTime, DeviceName, AccountName, ProcessCommandLine, ParentProcess, HasInsecureOrSilent;
let MatchedRecon =
    Downloads
    | join kind=inner (ReconEvents) on DeviceName
    | where ReconTimestamp between (DownloadTime - 30m .. DownloadTime)
    | summarize ReconCommandsSeen = make_set(ReconCommand, 5) by DownloadTime, DeviceName, AccountName, ProcessCommandLine, ParentProcess, HasInsecureOrSilent;
Downloads
| join kind=leftouter (MatchedExec) on DownloadTime, DeviceName, AccountName, ProcessCommandLine, ParentProcess, HasInsecureOrSilent
| join kind=leftouter (MatchedRecon) on DownloadTime, DeviceName, AccountName, ProcessCommandLine, ParentProcess, HasInsecureOrSilent
| extend ActivityType = strcat(
    "LOLBin Download (curl -> external IP literal)",
    iff(HasInsecureOrSilent, " [insecure/silent]", ""),
    iff(isnotempty(ReconCommandsSeen), strcat(" | preceded by recon: ", tostring(ReconCommandsSeen)), ""),
    iff(isnotempty(ExecFileNames), strcat(" -> executed: ", tostring(ExecFileNames)), ""))
| project DownloadTime, DeviceName, AccountName, ActivityType, ProcessCommandLine, ParentProcess, ReconCommandsSeen, ExecFileNames
| order by DeviceName, DownloadTime asc
```

## What a hit looks like
A result identifies the device and account that launched `curl`, the complete download command line, its parent process, and whether insecure or silent options were present. `ReconCommandsSeen` lists command-shell discovery activity during the preceding 30 minutes, while `ExecFileNames` lists selected interpreters or proxy-execution binaries launched on the same device within 10 minutes after the download.

## False positive notes
Administrators, developers, installers, and troubleshooting scripts may legitimately download packages from an IP literal or use silent `curl` options. Validate the destination IP, downloaded object, signer or hash, initiating account, parent process, and whether the subsequent process accessed the downloaded file. Approved internal automation that reaches public infrastructure by IP may require tuning by account, device group, destination, or known command-line pattern.

## Detection blind spots
The hunt does not inspect the downloaded file name or prove that a subsequent process executed that file; the temporal correlation is device-level. It does not detect downloads made with other utilities, hostnames, IPv6 literals, encoded or obfuscated URLs, or process activity outside the selected 30-day and correlation windows. Private-address exclusion is regex-based and does not validate whether an IPv4 octet is in the `0` through `255` range.

## Validation
This hunt has not yet been validated with Atomic Red Team or a live attack simulation. Before promotion beyond draft, test an external-IP `curl` download with and without preceding discovery commands and follow-on execution, then confirm expected results and measure benign matches in Defender XDR.

## References
- [MITRE ATT&CK T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK T1016: System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [MITRE ATT&CK T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [LOLBAS: Curl](https://lolbas-project.github.io/lolbas/Binaries/Curl/)

