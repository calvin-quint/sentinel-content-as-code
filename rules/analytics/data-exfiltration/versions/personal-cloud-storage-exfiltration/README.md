Progression of the personal-cloud-storage exfiltration rule, archived here to show how the detection matured. The current/production version lives at `../personal_cloud_storage_exfiltration.kql` (v6).

- **v1** — earliest version: 8 named personal-cloud domains, 4 DLP sensitive-info types, no org-domain origin check, simple count threshold
- **v2** — expands to ~30 named domains, adds org-domain origin filtering, 7 DLP types, still a low/noisy threshold (`FileCount >= 1`)
- **v3** — drops the named-domain blocklist for a simpler negative filter (anything not org/Azure = external), raises the threshold (`FileCount >= 10`)
- **v4** — broadens to 5 upload action types, drops domain filtering entirely, relies purely on DLP sensitive-info matches + joins `OfficeActivity` for DLP rule/policy context — the most portable version, no org-specific logic at all
- **v5** — keeps v4's DLP+OfficeActivity approach, reintroduces a directional check (must originate from org, must NOT target org — i.e. actually leaving the tenant), improves UPN extraction
- **v6 (current)** — combines everything: cheap string pre-filters before `parse_json` for performance, v5's directional check, re-adds the named high-risk-domain list from v2 as a secondary risk-tier signal rather than the primary filter, adds a `RiskScore` (Critical/High/Medium/Low)
