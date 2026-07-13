# sentinel-content-as-code

Microsoft Sentinel Analytics Rules managed as code. Rules are authored as
YAML, validated in CI on every pull request, and deployed automatically to
a Sentinel workspace via the Azure REST API when merged to `main`.

## Repository layout

```
rules/
  analytics/
    <category>/
      <rule-name>.yaml       # one Scheduled analytics rule per file
schemas/
  analytics-rule.schema.json # JSON Schema all rule YAML is validated against
scripts/
  rule_transform.py          # YAML -> Sentinel REST API body
  validate_rules.py          # schema + duplicate-id validation
  deploy_rules.py            # deploys (PUTs) rules via `az rest`
.github/workflows/
  validate-rules.yml         # runs on every PR touching rules/schemas/scripts
  deploy-rules.yml           # runs on push to main, deploys changed rules
```

Rules are grouped into folders by primary MITRE ATT&CK tactic (e.g.
`initial-access`, `credential-access`) purely for organization — the
folder name has no functional effect. Add new categories as needed.

## Authoring a rule

Copy an existing YAML file under `rules/analytics/<category>/` as a
starting point. Required fields:

| Field             | Notes                                                              |
|-------------------|---------------------------------------------------------------------|
| `id`              | GUID. Generate once with `uuidgen` / `[guid]::NewGuid()` and never change it — changing it creates a new rule instead of updating the existing one. |
| `name`            | Display name shown in Sentinel.                                    |
| `description`     | Free text.                                                         |
| `severity`        | `Informational` \| `Low` \| `Medium` \| `High`                     |
| `query`           | KQL query body.                                                    |
| `queryFrequency`  | ISO 8601 duration, e.g. `PT1H`.                                    |
| `queryPeriod`     | ISO 8601 duration, e.g. `PT1H`.                                    |
| `triggerOperator` | `gt` \| `lt` \| `eq` \| `ne`                                        |
| `triggerThreshold`| Integer.                                                            |

Optional fields (`tactics`, `relevantTechniques`, `entityMappings`,
`incidentConfiguration`, `eventGroupingSettings`, `suppressionEnabled`,
`suppressionDuration`, `customDetails`, `alertDetailsOverride`,
`requiredDataConnectors`) are documented in
[`schemas/analytics-rule.schema.json`](schemas/analytics-rule.schema.json).
`status` and `requiredDataConnectors` are metadata only and are not sent
to Sentinel.

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
  sent to Azure.
- **Pushes to `main`** run [`deploy-rules.yml`](.github/workflows/deploy-rules.yml):
  validates, then authenticates to Azure via OIDC and deploys every rule
  under `rules/analytics/` with an idempotent `PUT` to the
  `Microsoft.SecurityInsights/alertRules` REST API. Re-running is safe —
  rules are keyed by their `id`.

Deletion is not automated: removing a YAML file from the repo does **not**
delete the corresponding rule from Sentinel. Disable it in Sentinel (or set
`enabled: false` and redeploy) and delete it manually if needed.

## One-time Azure/GitHub setup

The deploy workflow authenticates with OIDC federated credentials (no
stored client secret). To set it up:

1. **Create (or reuse) an Azure AD App Registration** and note its
   Application (client) ID and your Azure AD Tenant ID.
2. **Grant it access to the Sentinel workspace**: assign the
   `Microsoft Sentinel Contributor` role on the workspace's resource
   group (or the workspace itself) to the App Registration's service
   principal.
3. **Add a federated credential** on the App Registration for GitHub
   Actions (Azure Portal → App registration → *Certificates & secrets* →
   *Federated credentials* → *GitHub Actions deploying Azure resources*):
   - Organization: your GitHub org/user
   - Repository: `sentinel-content-as-code`
   - Entity type: `Branch`
   - Branch: `main`
   - (Optionally add a second federated credential with Entity type
     `Environment` = `production` if you use the `production` GitHub
     Environment referenced in the workflow.)
4. **Set repository variables** (Settings → Secrets and variables →
   Actions → *Variables*, not secrets — none of these are sensitive on
   their own):
   - `AZURE_CLIENT_ID`
   - `AZURE_TENANT_ID`
   - `AZURE_SUBSCRIPTION_ID`
   - `AZURE_RESOURCE_GROUP` — resource group containing the Sentinel workspace
   - `AZURE_WORKSPACE_NAME` — Log Analytics workspace name that has Sentinel enabled
5. (Recommended) Create a GitHub **Environment** named `production` with
   required reviewers, and reference it from `deploy-rules.yml` (already
   wired up) so deploys need manual approval.

Once configured, merging a change under `rules/analytics/**` to `main`
deploys it automatically.
