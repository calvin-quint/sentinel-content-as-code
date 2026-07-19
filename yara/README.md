# yara/ — malware-family artifact detection

Sigma/KQL rules in this repo detect *behavior* in logs and telemetry.
YARA rules detect the *artifact itself* — byte patterns, strings, PE
characteristics in a file or in memory. This folder is specifically for
named-malware-family detections: the companion piece to a `threat_intel`
block that actually names a family, not a generic technique rule.

## Structure

```
yara/
  <malware-family>/       # e.g. asyncrat, darkgate — lowercase, matches
                            # threat_intel.family in the companion rule's frontmatter
    <rule-name>.yar
    README.md               # optional — family context, sample sources, references
```

## Linking a YARA rule to its companion KQL/Sigma rule

Set the KQL rule's frontmatter:

```yaml
threat_intel:
  family: AsyncRAT
  yara_rule: yara/asyncrat/asyncrat-loader.yar
```

The KQL/Sigma rule detects the family's C2/network behavior in telemetry;
the YARA rule identifies the actual binary/loader on disk or in memory.
Cross-reference both directions — the YARA rule's own header comment
should note which KQL rule it pairs with.

## Where these actually run

Nothing in this repo's CI deploys YARA rules automatically — there's no
Sentinel-native YARA execution. In practice these get used via:

- **Microsoft Defender for Endpoint Live Response** — run a YARA scan
  against a specific host during investigation (`run-script` / a custom
  Live Response library script wrapping `yara64.exe`).
- **Local/offline scanning** in `offsec-lab` — validate a rule actually
  matches a real (or a safely reproduced) sample before trusting it.

## Authoring conventions

- One rule per file, filename matches the rule name.
- Include a header comment: author, date, the malware family, and the
  companion KQL rule path if one exists.
- Prefer specific, tested strings/conditions over broad heuristics —
  a YARA rule that matches too much is worse than one that matches
  nothing, since false positives here mean quarantining legitimate files.
- Test against both a known-bad sample (if safely available, e.g. from a
  public malware repository under proper handling) and a clean baseline
  before treating a rule as reliable.
