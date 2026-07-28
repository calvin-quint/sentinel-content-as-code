# C5-KQL-GetURL

HTTP-triggered child playbook. Finds the most recent URL a user interacted
with in the last 2 hours — first from Safe Links click telemetry
(`UrlClickEvents`), falling back to any URL that was simply delivered to
their inbox (`EmailEvents` joined to `EmailUrlInfo`). Called by
`P2-UrlClick-SignIn` to locate the URL to correlate against post-click
sign-ins.

**Trigger body:** `IncidentId`, `UserPrincipalName`

**Response:** `ClickedURL`, `NetworkMessageId`, `IsClickedThrough`,
`ClickTime`, `URLSource` (`UrlClickEvents` / `EmailUrlInfo`), `URLFound`.

## Flow

```mermaid
flowchart TD
    T["HTTP trigger: UserPrincipalName"] --> A["Query_UrlClickEvents\nlast 2h"]
    T --> B["Query_EmailUrlInfo\nlast 2h"]
    A --> C{"Evaluate_Results\nUrlClickEvents hit?"}
    B --> C
    C -->|yes| D["Response_UrlClickEvents\nURLSource: UrlClickEvents"]
    C -->|no| E{"Check_EmailUrlInfo\nEmailUrlInfo hit?"}
    E -->|yes| F["Response_EmailUrlInfo\nURLSource: EmailUrlInfo"]
    E -->|no| G["Response_No_URL_Found\nURLFound: false"]
```
