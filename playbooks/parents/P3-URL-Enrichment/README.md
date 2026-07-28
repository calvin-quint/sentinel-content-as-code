# P3-URL-Enrichment

Sentinel-incident-triggered parent playbook. Pulls every URL entity on the
incident, filters out empty/image URLs, scans what's left through
urlscan.io, and escalates the incident if any URL comes back malicious.

**Trigger:** Microsoft Sentinel incident-creation webhook

**Calls:** `C2-Enrich-URL`, `C6-Notify-Teams` (via the incident comment; no
direct notify call — severity/comment only)

## Flow

```mermaid
flowchart TD
    T["Sentinel incident trigger"] --> I["Initialize variables\nURLResults, HasMaliciousURL, CommentBody"]
    I --> EU["Entities_Get_URLs"]
    EU --> FE["Filter_Empty_URLs"]
    FE --> FI["Filter_Image_URLs\n.png/.jpg/.gif/.svg/.ico excluded"]
    FI --> SU["Select_URL_Strings"]
    SU --> CU{"Check_URLs_Found\nany URLs left?"}

    CU -->|yes| FEU["For_each_URL"]
    subgraph URL["per URL"]
        C2["Call_C2_Enrich_URL"] --> P2r["Parse_C2_Response"]
        P2r --> UM{"IsMalicious?"}
        UM -->|yes| SM["Set_HasMaliciousURL"]
        SM --> AR["Append_URL_Result + CommentBody"]
        UM -->|no| AR
    end
    FEU --> C2

    AR --> CS{"Check_Severity\nHasMaliciousURL?"}
    CS -->|yes| SH["Update_Incident_High"]
    SH --> AM["Add_Comment_Malicious"]
    CS -->|no| AC["Add_Comment_Clean"]
    CU -->|no| AN["Add_Comment_No_URLs"]
```
