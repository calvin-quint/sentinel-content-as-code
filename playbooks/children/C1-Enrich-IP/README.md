# C1-Enrich-IP

HTTP-triggered child playbook. Enriches a single IP address from GeoIP, AbuseIPDB,
Sentinel threat intel, and the `TrustedIPs` watchlist, then rolls the results into
a risk tier. Called by `P1-Universal-Enrichment` for every IP entity on an incident.

**Trigger body:** `ipAddress` (required), `incidentArmId`

**Response:** `RiskTier` (`Trusted` / `Low` / `Medium` / `High`) plus the raw
GeoIP, AbuseIPDB, and threat-intel fields it was derived from.

## Flow

```mermaid
flowchart TD
    T["HTTP trigger: ipAddress"] --> A["Get_secret\n(AbuseIPDB-APIKey)"]
    T --> B["HTTP_GeoIP\nip-api.com"]
    T --> C["Run_KQL_ThreatIntel\nThreatIntelIndicators"]
    T --> D["Run_KQL_TrustedIPs\nTrustedIPs watchlist"]
    A --> E["HTTP_AbuseIPDB"]
    B --> F["Compose_Response\nmerge + compute RiskTier"]
    C --> F
    D --> F
    E --> F
    F --> G["Response 200 (JSON)"]
```

GeoIP, threat intel, and the watchlist lookup run in parallel with the
AbuseIPDB call; `Compose_Response` waits on all four regardless of
success/failure/timeout so a single failed source degrades the result
instead of failing the whole enrichment.
