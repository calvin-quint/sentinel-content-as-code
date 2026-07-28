# P1-Universal-Enrichment

Sentinel-incident-triggered parent playbook. Runs on every incident
(the general-purpose baseline enrichment): pulls every IP and account
entity, enriches each in parallel via the child playbooks, escalates and
remediates if anything comes back high-risk, and always leaves a summary
comment on the incident.

**Trigger:** Microsoft Sentinel incident-creation webhook

**Calls:** `C1-Enrich-IP`, `C4-Enrich-User`, `C10-Revoke-Sessions`,
`C7-Disable-Account`, `C6-Notify-Teams`

## Flow

```mermaid
flowchart TD
    T["Sentinel incident trigger"] --> I["Initialize variables\nIPResults, UserResults, HasHighRisk*"]
    I --> EI["Entities_Get_IPs"]
    I --> EA["Entities_Get_Accounts"]

    EI --> FI["For_each_IP"]
    subgraph IP["per IP"]
        C1["Call_C1_Enrich_IP"] --> P1r["Parse_C1_Response"]
        P1r --> RH{"RiskTier == High?"}
        RH -->|yes| SH["Set_HasHighRiskIP"]
        RH -->|no| AR["Append_IP_Result + Summary"]
        SH --> AR
    end
    FI --> C1

    EA --> FA["For_each_Account"]
    subgraph ACC["per Account"]
        C4["Call_C4_Enrich_User"] --> P4r["Parse_C4_Response"]
        P4r --> UH{"high-risk?\nEntraRisk=high OR\nEscalateToSOC OR\nInvestigationPriority>6"}
        UH -->|yes| SU["Set_HasHighRiskUser"]
        SU --> C10["Call_C10_Revoke_Sessions"]
        C10 --> PR{"IsPrivilegedAccount?"}
        PR -->|yes| C7["Call_C7_Disable_Account"]
        PR -->|no| AU1["Append_User_Result (high)"]
        C7 --> AU1
        UH -->|no| AU2["Append_User_Result (normal)"]
    end
    FA --> C4

    AR --> CK{"Check_RiskTier_High\nHasHighRiskIP OR HasHighRiskUser?"}
    AU1 --> CK
    AU2 --> CK
    CK -->|yes| SEV["Update_Incident_Severity_High"]
    SEV --> NT["Call_C6_Notify_Teams"]
    NT --> CH["Add_Comment_High_Risk"]
    CK -->|no| CS["Add_Comment_Standard"]
```

IP and account entities are enriched independently and in parallel; only
the final severity/comment step waits on both loops. A high-risk user gets
sessions revoked unconditionally, and the account disabled on top of that
only if it's also on the `PrivilegedAccounts` watchlist.
