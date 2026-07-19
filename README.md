# sentinel-content-as-code

Microsoft Sentinel content managed as code: detection rules, hunting
queries, and SOAR playbooks. Every rule and playbook is version-
controlled, validated in CI on every pull request, and deployed
automatically to a Sentinel workspace via the Azure REST API when
merged to `main`.

This repo merges what used to be three separate repos —
`kql-detection-rules` (rich per-rule documentation), the original
`sentinel-content-as-code` (the deployment pipeline), and `soar`/
`sentinel-automation` (SOAR playbooks/watchlists) — into one, so
detection content and its deployment pipeline live in the same place.

## Repository layout

```
rules/
  analytics/
    <category>/
      <rule-name>.md          # frontmatter (MITRE mapping, threat-intel context,
                                # validation status, ARM deploy config) + full narrative
                                # doc + embedded query — see TEMPLATE.md
      versions/                # optional: archived prior query iterations (not deployed)
hunting/
  <category>/
    <query-name>.md            # saved-search / enrichment queries — same template,
                                 # no `analytics_rule` block, not deployed by this pipeline
sigma/
  <category>/
    <rule-name>.yml             # Sigma-authored source for rules where a Sigma→Kusto
                                  # conversion path exists (ASIM-normalized tables today) —
                                  # see sigma/README.md for which rules qualify and why
playbooks/
  parents/                     # Sentinel-triggered Logic Apps — orchestrate enrichment,
                                 # write incident comments, trigger remediation
  children/                    # HTTP-triggered Logic Apps — one action each (enrich an
                                 # IP/URL/hash/user, run a KQL query, notify Teams, disable
                                 # an account, revoke sessions), return structured JSON only
automations/
  <name>/                      # Timer-triggered Logic Apps, independent of incidents
watchlists/
  *.csv                        # TrustedIPs, ServiceAccounts, PrivilegedAccounts,
                                 # PlaybookOverride, SanctionedTools
schemas/
  analytics-rule.schema.json   # JSON Schema the derived ARM properties of every
                                 # deployable rule are validated against
scripts/
  rule_transform.py            # parses a rule .md's frontmatter + Sentinel query block
                                 # into a Sentinel alertRules REST API body
  validate_rules.py            # schema + duplicate-id + query-resolution validation
  deploy_rules.py               # deploys (PUTs) rules via `az rest`
  deploy-playbook.py            # deploys a single Logic App playbook/automation
  sync-watchlist.sh             # uploads watchlist CSVs to Sentinel
  validate-watchlists.py        # checks watchlist column headers
.github/workflows/
  validate-rules.yml            # PR: schema validation + dry-run deploy payload build
  deploy-rules.yml               # push to main: deploys changed/all analytics rules
  deploy-playbooks.yml           # push to main: deploys changed/all playbooks
  sync-watchlists.yml            # push to main: uploads watchlist CSVs
  validate-watchlists.yml        # PR: validates watchlist CSV headers
```

Rules are grouped into folders by category (e.g. `identity`,
`credential-access`, `aitm-and-token-theft`, `ransomware`, `network`)
purely for organization — the folder name has no functional effect. Add
new categories as needed.

## Detection page format

Every rule is a single Markdown page (see [`TEMPLATE.md`](TEMPLATE.md)):
YAML frontmatter carrying MITRE ATT&CK mapping, named-threat/threat-
intel context (or an explicit "no named threat" statement), Atomic Red
Team validation status, and — for anything deployed as a live Sentinel
analytics rule — an `analytics_rule` block matching the ARM schema
almost field-for-field. The body is a fixed set of sections: Summary,
Hypothesis, Threat intelligence context, Query (Defender XDR and/or
Sentinel, labeled), Analytics rule configuration, What a hit looks
like, False positive notes, Detection blind spots, Validation,
References.

`rule_transform.py` derives the deployable ARM properties directly from
the page: `name` from the title, `description` from the Summary
section, `severity` from the frontmatter (capitalized; `critical` maps
to ARM's `High`, since ARM has no Critical enum value), and `query`
from the fenced `kusto` block under the **Sentinel** label in the Query
section. Pages with no `analytics_rule` block (hunting/lookup queries,
narrative-only pages) are parsed but never deployed.

## Authoring a rule

Copy [`TEMPLATE.md`](TEMPLATE.md) as a starting point. Required
frontmatter for a deployable rule's `analytics_rule` block:

| Field | Notes |
|---|---|
| `id` | GUID. Generate once with `uuidgen` / `[guid]::NewGuid()` and never change it — changing it creates a new rule instead of updating the existing one. |
| `queryFrequency` / `queryPeriod` | ISO 8601 duration, e.g. `PT1H`. |
| `triggerOperator` / `triggerThreshold` | e.g. `gt` / `0`. |

`name`, `description`, `severity`, and `query` are **not** set directly
in `analytics_rule` — they're derived from the page's title, Summary
section, top-level `severity` field, and Query section respectively.
Optional ARM fields (`tactics`, `relevantTechniques`, `entityMappings`,
`incidentConfiguration`, `eventGroupingSettings`, `customDetails`,
`alertDetailsOverride`, `requiredDataConnectors`) are documented in
[`schemas/analytics-rule.schema.json`](schemas/analytics-rule.schema.json).

Only the `Scheduled` rule kind is currently supported.

### Validating locally

```bash
cd scripts
pip install -r requirements.txt
python validate_rules.py ../rules/analytics
python deploy_rules.py ../rules/analytics --dry-run   # prints what would deploy, makes no changes
```

## CI/CD

- **Pull requests** touching `rules/`, `schemas/`, or `scripts/` run
  [`validate-rules.yml`](.github/workflows/validate-rules.yml): schema
  validation plus a dry run of the deployment payload build. Nothing is
  sent to Azure. Playbook/automation JSON is validated by
  [`validate-playbooks` step in `deploy-playbooks.yml`](.github/workflows/deploy-playbooks.yml)
  on push, and watchlist headers by
  [`validate-watchlists.yml`](.github/workflows/validate-watchlists.yml).
- **Pushes to `main`** run [`deploy-rules.yml`](.github/workflows/deploy-rules.yml):
  validates, then authenticates to Azure via OIDC and deploys every
  deployable rule under `rules/analytics/` with an idempotent `PUT` to
  the `Microsoft.SecurityInsights/alertRules` REST API. Re-running is
  safe — rules are keyed by their `id`. [`deploy-playbooks.yml`](.github/workflows/deploy-playbooks.yml)
  and [`sync-watchlists.yml`](.github/workflows/sync-watchlists.yml)
  similarly deploy changed playbooks/automations and sync watchlist
  CSVs.

Deletion is not automated: removing a rule's `.md` file does **not**
delete the corresponding rule from Sentinel. Disable it in Sentinel (or
set `analytics_rule.enabled: false` and redeploy) and delete it
manually if needed.

## SOAR playbook architecture

```
Sentinel Incident
       │
       ▼
 ┌─────────────┐     HTTP POST      ┌──────────────────────┐
 │  Parent (P) │ ─────────────────► │     Child (C)        │
 │  Orchestrates│                   │  Enriches / Acts     │
 │  Comments   │ ◄─── JSON body ─── │  Returns data only   │
 └─────────────┘                    └──────────────────────┘
```

**Parents** are Sentinel-triggered — they orchestrate enrichment calls,
evaluate risk, write incident comments, update severity, and trigger
remediations. **Children** are HTTP-triggered — each does one thing
(call an external API, run a KQL query, take a Graph action) and
returns structured JSON; they never write Sentinel comments.
**Automations** run on a timer, independent of incidents.

| Children | What it does |
|---|---|
| C1 Enrich-IP | GeoIP + AbuseIPDB + Sentinel TI + TrustedIPs watchlist → RiskTier |
| C2 Enrich-URL | urlscan.io submit → result → ThreatLevel/IsMalicious/Score |
| C3 Enrich-Hash | VirusTotal v3 file lookup → ThreatLevel |
| C4 Enrich-User | Graph profile + Entra risk + KQL SigninLogs/UEBA/watchlists/prior incidents |
| C5 KQL-GetURL | Parallel KQL (UrlClickEvents + EmailUrlInfo) to find clicked URLs |
| C6 Notify-Teams | Posts to Teams SOC channel, themed by severity |
| C7 Disable-Account | Graph `accountEnabled: false` via Managed Identity |
| C10 Revoke-Sessions | Graph `revokeSignInSessions` via Managed Identity |

| Parents | Trigger | What it does |
|---|---|---|
| P1 Universal-Enrichment | Incident creation | Enriches all IP/account entities in parallel; revokes+disables for high-risk users |
| P2 UrlClick-SignIn | Incident creation | URL lookup → enrich + post-click behavior + user profile; 3-tier outcome |
| P3 URL-Enrichment | Incident creation | Extracts URL entities, scans each, builds per-URL comment |
| P4 ImpossibleTravel | Incident creation | Parallel user enrich + impossible-travel KQL; revoke+disable |
| P5 AccountCompromise | Incident creation | Parallel user enrich + failed-signin KQL; revoke+disable |

| Automations | Schedule | What it does |
|---|---|---|
| A1 Notify-SD-UserDisabled | Every 15 min | Emails Service Desk when an automated sync app disables an account |

### Placeholder tokens

Playbook definitions use `__PLACEHOLDER__` tokens substituted at deploy
time by `scripts/deploy-playbook.py` — see that script and the GitHub
repository variables/secrets it expects (`AZURE_SUBSCRIPTION_ID`,
`SENTINEL_RESOURCE_GROUP`, `SENTINEL_WORKSPACE_NAME`, per-playbook
`C*_TRIGGER_URL` secrets, etc.) before the first deploy.

### Watchlists

| Watchlist | SearchKey | Purpose |
|---|---|---|
| `TrustedIPs.csv` | CIDR or IP | IPs always scored Trusted regardless of AbuseIPDB score |
| `ServiceAccounts.csv` | UPN | Accounts excluded from anomaly escalation |
| `PrivilegedAccounts.csv` | UPN | Accounts triggering account-disable on compromise |
| `PlaybookOverride.csv` | UPN or IP | Temporary suppression with expiry date |
| `SanctionedTools.csv` | Tool name/hash | Approved software excluded from hash alerts |
| `BrandDomains.csv` | Domain | Seeded brand/vendor root domains for the lookalike-domain rule (create if not present) |

## One-time Azure/GitHub setup

The deploy workflows authenticate with OIDC federated credentials (no
stored client secret).

1. **Create (or reuse) an Azure AD App Registration** and note its
   Application (client) ID and your Azure AD Tenant ID.
2. **Grant it access to the Sentinel workspace**: assign
   `Microsoft Sentinel Contributor` (for rules) and `Logic App
   Contributor` (for playbooks) on the relevant resource group(s).
3. **Add a federated credential** for GitHub Actions (Azure Portal →
   App registration → *Certificates & secrets* → *Federated
   credentials*):
   - Entity type: `Branch`, Branch: `main` (and optionally `Environment`
     = `production`, matching the `production` GitHub Environment these
     workflows reference).
4. **Set repository variables/secrets** (Settings → Secrets and
   variables → Actions):
   - Variables: `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
     `AZURE_RESOURCE_GROUP`, `AZURE_WORKSPACE_NAME`,
     `SENTINEL_RESOURCE_GROUP`, `SENTINEL_WORKSPACE_NAME`,
     `AZURE_LOCATION`, `PLAYBOOK_NAME_PREFIX`, `TENANT_DOMAIN`,
     `SYNC_APP_NAME`, `ORG_NAME`
   - Secrets: `AZURE_CLIENT_ID`, per-playbook `C*_TRIGGER_URL`,
     `AUTOMATION_SENDER_UPN`, `SERVICEDESK_EMAIL`
5. (Recommended) Create a GitHub **Environment** named `production`
   with required reviewers.

Once configured, merging a change under `rules/analytics/**`,
`playbooks/**`, `automations/**`, or `watchlists/**` to `main` deploys
it automatically.

## Origin note

The detection content here previously lived duplicated across
`calvin-quint/docs` (`01-detection-engineering/kql/`),
`calvin-quint/kql-detection-rules`, and this repo; the SOAR content
duplicated across `calvin-quint/soar` and `calvin-quint/sentinel-
automation`. This repo is now the single source of truth for both —
`docs`' copy should be treated as historical/deprecated going forward,
not a place to make new edits.
