# sigma/ — Sigma-sourced detections

A subset of rules in `rules/analytics/` are authored in [Sigma](https://sigmahq.io/)
first, then converted to the Sentinel KQL that actually gets deployed —
rather than writing KQL directly. This folder holds those Sigma sources.

## Why only some rules

Sigma's Sentinel conversion path (`pysigma-backend-kusto`'s `sentinelasim`
pipeline) targets [ASIM](https://learn.microsoft.com/azure/sentinel/normalization)-normalized
tables (`_Im_Dns`, `_Im_WebSession`, etc.), not the native Defender/Entra
tables (`SigninLogs`, `DeviceProcessEvents`) most of this repo's existing
rules query directly. A rule has to target an ASIM-normalized source to be
a realistic Sigma-first candidate today.

`network/lookalike-domain-detected.md` and
`network/newly-registered-domain-first-seen.md` already use the ASIM
`_Im_Dns` parser — they're the first real candidates. Native-table rules
stay KQL-first until either a custom pySigma pipeline is written for them
or they're re-pointed at ASIM equivalents.

## Structure

```
sigma/
  <category>/            # same category names as rules/analytics/
    <rule-name>.yml       # native Sigma rule
```

## Workflow

```bash
pip install sigma-cli pysigma-backend-kusto

# Validate syntax
sigma check sigma/network/lookalike-domain-detected.yml

# Convert to Sentinel KQL (ASIM pipeline)
sigma convert -t kusto -p sentinelasim sigma/network/lookalike-domain-detected.yml
```

Paste/reconcile the converted output into the corresponding rule's `.md`
file under the **Sentinel** query block in its `## Query` section, and set
that rule's `sigma_source` frontmatter field (see `TEMPLATE.md`) to the
path of the `.yml` file — that's what marks a rule as Sigma-sourced rather
than KQL-first, and is what a future CI drift check (comparing the live
`.md` query against a fresh `sigma convert` run) would key off.

This isn't wired into `validate_rules.py`/`deploy_rules.py` yet — those
scripts read the `.md`'s embedded Sentinel query regardless of whether it
originated from Sigma. The `.yml` here is the authoring source and a
portability artifact (the same rule converts to Splunk/Elastic/etc. via a
different pySigma backend), not a second deploy path.
