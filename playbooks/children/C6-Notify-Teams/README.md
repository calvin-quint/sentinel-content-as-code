# C6-Notify-Teams

HTTP-triggered child playbook. Posts a SOC alert card to a Teams webhook,
color-coded by severity, with a deep link back to the incident in Sentinel.
Called by every parent playbook when it escalates an incident to High.

**Trigger body:** `IncidentTitle` (required), `Severity`, `AlertDetails`,
`IncidentUrl`, `IncidentId`

**Response:** `Success`, `StatusCode`, `SentAt`

## Flow

```mermaid
flowchart TD
    T["HTTP trigger: IncidentTitle, Severity, AlertDetails"] --> A["Get_Teams_Webhook\n(Teams-SOC-Webhook secret)"]
    T --> B["Compose_ThemeColor\nSeverity -> hex color"]
    A --> C["HTTP_Send_Teams\nMessageCard POST"]
    B --> C
    C --> D["Response 200 (JSON)"]
```

`Compose_ThemeColor` maps `High` → red, `Medium` → orange, `Low` → yellow,
anything else → Sentinel blue.
