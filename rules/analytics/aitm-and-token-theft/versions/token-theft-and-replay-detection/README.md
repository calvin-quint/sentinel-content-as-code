Progression of the token-theft/replay detection rule. The current/production
version is `../../Token Theft and Replay Detection.kql`. These were
previously scattered across the `identity/` folder under unrelated generic
names (a naming artifact from the original migration) — archived here to
show the actual lineage.

- **v1** — earliest version: 7-day window, `Location != "US"`, requires
  `ConditionalAccessStatus == "notApplied"`. Geography-based, no correlation.
- **v2** — pivots to risk-based targeting instead of geography:
  `RiskLevelDuringSignIn == "high"` + `ConditionalAccessStatus == "success"`.
  More precise, still no enrichment.
- **v3** — adds a self-join against the user's own prior sign-in to compute
  impossible country/state/city travel, broadens `ResultType` to catch
  partial-MFA/token-replay/expired-token outcomes, adds a `SignInOutcome` label.
- **Final (current)** — takes v3's structure and broadens the trigger
  condition from AND to OR, adding a third path (approved mobile-app
  notification) that v3 would have missed.
