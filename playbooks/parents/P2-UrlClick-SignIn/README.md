# P2-UrlClick-SignIn

Sentinel-incident-triggered parent playbook. For each account on the
incident, finds the URL they most recently interacted with and checks
whether a sign-in happened in the 30 minutes after the click — the
phishing-to-credential-use correlation. Escalates hardest when both a
malicious URL *and* a post-click sign-in are confirmed together.

**Trigger:** Microsoft Sentinel incident-creation webhook

**Calls:** `C5-KQL-GetURL`, `C2-Enrich-URL`, `C4-Enrich-User`,
`C6-Notify-Teams`

## Flow

```mermaid
flowchart TD
    T["Sentinel incident trigger"] --> I["Initialize variables\nURLResults, HasMaliciousURL, HasPostClickSignIn"]
    I --> EA["Entities_Get_Accounts"]
    EA --> FA["For_each_Account"]

    subgraph ACC["per Account"]
        C5["Call_C5_GetURL"] --> P5r["Parse_C5_Response"]
        P5r --> UF{"URLFound?"}
        UF -->|yes| C2["Call_C2_Enrich_URL"]
        UF -->|yes| KQ["KQL_PostClick_SignIn\n30-min window"]
        UF -->|yes| C4a["Call_C4_WithURL"]
        C2 --> P2r["Parse_C2_Response"] --> UM{"IsMalicious?"}
        UM -->|yes| SM["Set_HasMaliciousURL"]
        KQ --> PC{"sign-in in window?"}
        PC -->|yes| SP["Set_HasPostClickSignIn"]
        SM --> AP["Append_URL_Result"]
        SP --> AP
        C4a --> AP
        UF -->|no| C4b["Call_C4_NoURL"] --> AN["Append_NoURL_Result"]
    end
    FA --> C5

    AP --> AS{"Assess_Risk\nmalicious URL AND post-click sign-in?"}
    AN --> AS
    AS -->|yes| SEV["Update_Incident_High"]
    SEV --> NT["Call_C6_Notify_Teams"]
    NT --> CC["Add_Comment_Critical"]
    AS -->|no| MO{"malicious URL only?"}
    MO -->|yes| SEM["Update_Incident_Medium"]
    SEM --> CM["Add_Comment_Malicious_URL"]
    MO -->|no| CN["Add_Comment_No_Threat"]
```
