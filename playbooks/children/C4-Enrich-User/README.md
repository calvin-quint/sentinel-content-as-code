# C4-Enrich-User

HTTP-triggered child playbook. Builds a full risk profile for a user: Entra
profile/manager, Entra ID Protection risk, 90-day sign-in history, UEBA
investigation priority, `IdentityInfo`, watchlist membership
(`ServiceAccounts` / `PrivilegedAccounts`), and prior-incident count. The
most heavily used child — called by every parent playbook (`P1`, `P2`,
`P4`, `P5`) for each account entity.

**Trigger body:** `UserPrincipalName` (required), `incidentArmId`

**Response:** `EntraRiskLevel`, `InvestigationPriority`, `IsPrivilegedAccount`,
`IsServiceAccount`, `IsDormant`, `MFABypassRisk`, `EscalateToSOC`, plus
manager, sign-in history, and prior-incident fields. Short-circuits with
`EarlyExit: true` if the account is already disabled.

## Flow

```mermaid
flowchart TD
    T["HTTP trigger: UserPrincipalName"] --> A["Graph_Get_User_Profile"]
    A --> B["Parse_User_Profile"]
    B --> C{"Account_Disabled?"}
    C -->|yes| D["Response_EarlyExit\nEarlyExit: true"]
    C -->|no| E["Graph_Get_Manager"]
    C -->|no| F["Graph_Get_Entra_Risk"]
    C -->|no| G["KQL_SigninLogs_History\n90d baseline"]
    C -->|no| H["KQL_IdentityInfo"]
    C -->|no| I["KQL_UEBA\nBehaviorAnalytics"]
    C -->|no| J["KQL_Watchlists\nServiceAccounts / PrivilegedAccounts"]
    C -->|no| K["KQL_Prior_Incidents\n30d"]
    E --> L["Compute_AccountAgeDays"]
    F --> L
    G --> L
    H --> L
    I --> L
    J --> L
    K --> L
    L --> M["Compose_Response\nrisk profile + EscalateToSOC"]
    M --> N["Response 200 (JSON)"]
```

`EscalateToSOC` is set when Entra risk is `high`, UEBA
`InvestigationPriority` exceeds 6, or the account is on the
`PrivilegedAccounts` watchlist — that flag is what parent playbooks branch
on to trigger session revocation and account disable.
