# P5-AccountCompromise

Sentinel-incident-triggered parent playbook. For each account on the
incident, checks the last 2 hours for brute-force-style failed sign-ins
(>10) or elevated Entra/UEBA risk, and remediates immediately if any
compromise threshold is met.

**Trigger:** Microsoft Sentinel incident-creation webhook

**Calls:** `C4-Enrich-User`, `C10-Revoke-Sessions`, `C7-Disable-Account`,
`C6-Notify-Teams`

## Flow

```mermaid
flowchart TD
    T["Sentinel incident trigger"] --> I["Initialize variables\nHasCompromisedUser, UserResults, UserSummary"]
    I --> EA["Entities_Get_Accounts"]
    EA --> FA["For_each_Account"]

    subgraph ACC["per Account"]
        C4["Call_C4_Enrich_User"]
        KQ["KQL_Failed_SignIns\nlast 2h"]
        C4 --> P4r["Parse_C4_Response"]
        KQ --> EV{"Evaluate_Compromise_Risk\nFailedSignIns>10 OR\nEntraRisk=high OR\nEscalateToSOC?"}
        P4r --> EV
        EV -->|yes| SC["Set_HasCompromisedUser"]
        SC --> C10["Call_C10_Revoke"]
        C10 --> PR{"IsPrivilegedAccount?"}
        PR -->|yes| C7["Call_C7_Disable"]
        PR -->|no| AC["Append_UserResult (compromised)"]
        C7 --> AC
        EV -->|no| AN["Append_UserResult (normal)"]
    end
    FA --> C4
    FA --> KQ

    AC --> CC{"Check_Compromise\nHasCompromisedUser?"}
    AN --> CC
    CC -->|yes| SEV["Update_Incident_High"]
    SEV --> NT["Call_C6_Notify_Teams"]
    NT --> CD["Add_Comment_Compromised"]
    CC -->|no| CN["Add_Comment_No_Compromise"]
```
