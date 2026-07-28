# P4-ImpossibleTravel

Sentinel-incident-triggered parent playbook. For each account on the
incident, checks the last 4 hours of sign-ins for successful logons from
more than one country — impossible/implausible travel — and remediates
immediately if found.

**Trigger:** Microsoft Sentinel incident-creation webhook

**Calls:** `C4-Enrich-User`, `C10-Revoke-Sessions`, `C7-Disable-Account`,
`C6-Notify-Teams`

## Flow

```mermaid
flowchart TD
    T["Sentinel incident trigger"] --> I["Initialize variables\nHasImpossibleTravel, UserResults, UserSummary"]
    I --> EA["Entities_Get_Accounts"]
    EA --> FA["For_each_Account"]

    subgraph ACC["per Account"]
        C4["Call_C4_Enrich_User"]
        KQ["KQL_Impossible_Travel\nlast 4h, DistinctCountries > 1"]
        C4 --> P4r["Parse_C4_Response"]
        KQ --> ET{"Evaluate_Travel_Risk\ntravel rows found?"}
        P4r --> ET
        ET -->|yes| ST["Set_HasImpossibleTravel"]
        ST --> C10["Call_C10_Revoke"]
        C10 --> PR{"IsPrivilegedAccount?"}
        PR -->|yes| C7["Call_C7_Disable"]
        PR -->|no| AT["Append_UserResult (travel)"]
        C7 --> AT
        ET -->|no| AN["Append_UserResult (normal)"]
    end
    FA --> C4
    FA --> KQ

    AT --> CT{"Check_Impossible_Travel\nHasImpossibleTravel?"}
    AN --> CT
    CT -->|yes| SEV["Update_Incident_High"]
    SEV --> NT["Call_C6_Notify_Teams"]
    NT --> CD["Add_Comment_Travel_Detected"]
    CT -->|no| CN["Add_Comment_No_Travel"]
```
