Progression of the AiTM token-replay detection rule. The current/production
version is `../../AiTM Token Replay Detection.kql`.

- **v1** — narrow, Graph-API-specific: joins a token's issuance (`SigninLogs`)
  against its use (`MicrosoftGraphActivityLogs`) and flags when the Graph API
  call comes from a different IP than the one the token was issued to, within
  a 24-hour window. Catches one specific abuse path — a stolen token used to
  call Graph directly.
- **Final (current)** — broader and baseline-driven: works purely off
  `SigninLogs`, builds a 14-day known-IP baseline and 90-day known-country
  baseline per user, and flags any token used across multiple IPs/countries
  within a 30-day window. Combines new-IP, new-country, multi-IP+country
  session, token-replay result codes, PRT usage, and MFA-bypass into a
  weighted `SignalScore` instead of a single hard-coded condition — a more
  general detection that doesn't depend on Graph API activity being present.
