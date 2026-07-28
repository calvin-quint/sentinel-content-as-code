# C2-Enrich-URL

HTTP-triggered child playbook. Submits a URL to urlscan.io, waits for the scan
to finish, and returns a threat verdict. Called by `P2-UrlClick-SignIn` and
`P3-URL-Enrichment` for each URL entity/click found on an incident.

**Trigger body:** `URL` (required), `NetworkMessageId`, `incidentArmId`

**Response:** `ThreatLevel` (`Low` / `Medium` / `High`), `IsMalicious`,
`ThreatScore`, tags/categories, screenshot and scan report URLs.

## Flow

```mermaid
flowchart TD
    T["HTTP trigger: URL"] --> A["Get_URLScan_Secret\n(URLScan-APIKey)"]
    A --> B["HTTP_Submit_Scan\nurlscan.io /scan"]
    B --> C["Wait_For_Scan\n20s"]
    C --> D["HTTP_Get_Result\nurlscan.io /result"]
    D --> E["Compose_Response\nverdict + ThreatLevel"]
    E --> F["Response 200 (JSON)"]
```

The 20-second wait is fixed, not polled — urlscan.io scans are async and
this playbook takes the best-effort result available at that point rather
than looping until `ScanComplete` is true.
