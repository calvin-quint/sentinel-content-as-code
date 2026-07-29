# OMNIA KQL Master Index — deep search pass 2 (2026-07-28)

This is the full accounting after a much deeper pass through conversation
history (15+ targeted searches beyond the first pass). Status per query:
**[FULL]** = literal KQL text recovered and saved to a file in this zip.
**[PARTIAL]** = some literal text recovered but truncated/incomplete in source.
**[NAMED ONLY]** = query is referenced by name/description in a summary or
inventory list, but no literal KQL text could be retrieved from search —
recovering it would mean rewriting from description, which is not the same
as your original query and is not included as if it were.

---

## 1. skill_library/ (11 files) — [FULL, from live skill folder]
All validated IR-2026-004 detection/hunting queries currently in
/mnt/skills/user/omnia-security-ir/references/kql/

## 2. project_files/ — [FULL]
OMNIA_UserCompromise_Correlation_Final.kql — 9-stage correlation query

## 3. extracted_from_docs/ (54 blocks) — [FULL]
Every KQL block embedded in the Bookmark Checklist, IR Playbook, and Vishing IR report

## 4. past_chats/proactive_hunting_package_10q/ — [FULL — all 10]
From "Proactive threat hunting queries and techniques" (2026-06-29):
1. EvilTokens/Storm-2372 device code lure-to-auth correlation
2. QR code quishing volume audit + click-through follow-up (2 queries)
3. OAuth silent redirect abuse (admin consent volume by actor)
4. Graph API sendMail post-ATO (new-IP sendMail calls)
5. OAuth app mailbox bulk read recon (GraphRunner/AzureHound pattern)
6. Admin By Request privilege abuse (Jordan Buser hypothesis pattern)
7. SVG/HTML attachment smuggling (Q1 2026 mega-campaign pattern)
8. Stale high-risk OAuth app inventory (dormant persistence)
9. Non-interactive sign-in velocity anomalies (token replay early warning)
10. After-hours Entra app registration credential adds

## 5. past_chats/insider_risk_aitm_gaps_20260626/ — [5 FULL, 1 PARTIAL]
From "KQL queries for insider risk and AITM detection" (2026-06-26):
1. Golden SAML — federation settings modified [FULL]
2. Conditional Access policy tampering [FULL]
3. Privileged role assignment outside PIM [FULL]
4. ClickFix/LOLBin execution chain (3 sub-queries: LOLBin from Office parent,
   certutil decode, encoded PowerShell) [FULL]
5. Cloud persistence via SP credential abuse [PARTIAL — cut off after `extend
   ActorUPN = ...`, remainder not recoverable via search]
6. MicrosoftGraphActivityLogs enrichment join (delegated + app-only via
   UniqueTokenId/UniqueTokenIdentifier) [FULL]

**[NAMED ONLY]** from this same session (per your own later recap, not recoverable verbatim):
- IP-plus-time-window fallback correlation for Graph logs
- OAuth app consent pivot via AuditLogs (AppId → AuditLogs consent records)
- Hardened campaign URL click + post-click sign-in correlation (dual-method union)
- Per-user click rate summary (blast radius companion)

## 6. past_chats/ (individually recovered, single files) — [FULL]
- User_Invite_All_permission_audit.kql — "KQL query for User.Invite.All permissions" (2026-07-16)
- DCSync_AlertEvidence_EntityType_Gotcha.kql — "Security investigation checklist" (2026-07-24), 4 queries
- InboxRule_Forwarding_Audit_IRSOP_5.1.kql — "Centralized IR reference documentation" (2026-06-24), 4 queries

---

## NAMED-ONLY QUERIES — exist, but literal text not recoverable from search

These are confirmed to have been built in past sessions (named specifically,
sometimes with schema/field details in the summary) but conversation_search
could not surface the literal KQL text — likely because the session is old
enough that only an AI-generated summary remains, not the raw transcript.

### "Anomalous sign-in queries and false positives" session (2026-07-02) — ~55 query inventory
This session itself was an attempt to recover a large historical body of work.
Categories confirmed to exist somewhere in your history, by name:

**Structural gap-fill analytics (6):**
- AADServicePrincipalSignInLogs table health verification
- SP new-IP authentication vs 14-day baseline
- SP credential-add then immediate auth from new IP (chain)
- CopilotActivity table health verification
- Copilot anomalous daily interaction spike
- Copilot burst data-retrieval operations (15-min window)
- Fusion silent-rule audit (disabled rules feeding Fusion)
- AADRiskyServicePrincipals custom operationalization
- Conditional Access report-only bypass detection
- Direct Send no-auth delivery bypass
(this list runs to 10, not 6 — your own recap in-session miscounted; noting as-is)

**SP sign-in log hunting package (4-tier, ~15-20 queries):**
- Tier 0: health checks — AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs,
  AADRiskyServicePrincipals, MicrosoftGraphActivityLogs
- Tier 1: SP auth inventory, orphaned SP detection, error code decoding
  (reference table: codes 0, 7000215, 7000222, 700027, 500011, 65001, 700082),
  long-lived credential inventory
- Tier 2: credential stuffing, new-ASN authentication, new-credential-immediate-use,
  resource scope expansion, suspicious user agents (ROADtools/GraphRunner/AADInternals),
  dormant SP reactivation spikes
- Tier 3: Graph API abuse post-auth — mailbox read, sendMail, directory enumeration
  recon, oAuth2PermissionGrant escalation
- Tier 4: managed-identity-specific — external IP auth, new resource access

**Four tuned OOB-rule replacements (2026-07-02):**
- Anomalous Sign-in Activity (BehaviorAnalytics + Anomalies table — the Anomalies-based
  version predates this project and was confirmed NOT recoverable even in that session)
- Unusual Auth Outside Normal Business Hours
- Successful Signin From Non-Compliant Device
- Unfamiliar Sign-in Properties

**New IP + Inbox Rule correlation (2026-04-14 session, distinct from the IR SOP version):**
- "Detecting suspicious sign-ins and inbox rule changes" — SigninLogs + CloudAppEvents,
  later revised with join kind=anti, ipv4_is_private(), BehaviorAnalytics enrichment

### Other named-only queries from single-topic sessions:
- "KQL query for outgoing emails" (2026-05-12) — EmailEvents/EmailAttachmentInfo/
  OfficeActivity exfil risk-scoring query with weighted scoring
- "KQL query for admin consent approval" (2026-05-14) — AuditLogs approval query +
  business-hours variant
- "KQL query for mailbox rule changes" (2026-04-14) — 3-query OfficeActivity/
  CloudAppEvents set (this predates and differs from the IR SOP 5.1 version, which
  IS recovered)
- ABR "Suspicious or Weak Elevation Justification" query (2026-05-14, "Sentinel rules
  for admin by request logs") — full field-level query built against real
  AdminByRequestLogs_CL schema (reason_s, user_email_s, elevatedApplications_s, etc.)
  and the follow-up personal-cloud-storage-install detection query
- EZRadius queries (same 2026-05-14 session) — across EZRadiusAuthentication_CL,
  EZRadiusPolicy_CL, EZRadiusAdministrator_CL, EZRadiusAccounting_CL
- InboxRule_Changes_ByUser (2026-07-08, "Revoking sessions for security" / Jim Cary
  investigation) — CloudAppEvents extract()-based rule parser with HasForwarding/
  IsExternalRecipient/IsBlankCondition derived fields
- AiTM UniqueTokenIdentifier cross-IP detection — two variants (direct join +
  14-day baseline/set_difference version) referenced in "AiTM detection and IR
  playbook technical documentation" (2026-07-20) but literal text not recovered
- DCSync rights audit KQL (EventID 4662 + extended-right GUIDs) from "Active Directory
  hardening and attack paths" (2026-07-26) — PowerShell ACL script was described in
  detail but the companion KQL query text itself wasn't surfaced verbatim
- Device code auth analytics rule query (2026-04-14, "Device code authentication
  analysis") — SigninLogs AuthenticationProtocol == "deviceCode" query, described
  but not returned verbatim
- Various one-off incident-investigation queries scattered across dozens of ticket/
  alert triage sessions (e.g. Wacatac/SVG smuggling correlation queries, DeviceProcessEvents/
  DeviceNetworkEvents pulls for individual host investigations, EmailAttachmentInfo hash
  correlation queries) — these are typically incident-specific one-liners built and
  used once; recovering literal text for all of them individually was not
  practical within this pass but they follow the same patterns already captured
  in skill_library/ and extracted_from_docs/

---

## 7. past_chats/IR-2026-004_Marcie_Gabriella_investigation/ — [FULL, 5 files/~9 queries]
- LocalGroup/PasswordReset endpoint + AD queries (3 queries)
- Multi-interface RPC coercion detection (PetitPotam/PrinterBug/ShadowCoerce/DFSCoerce/WSPCoerce)
- Salesforce/Dayforce network check during attacker call windows
- Downloads-during-call-windows query
- cmd.exe recon commands on both victim devices

---

## IMPORTANT: this exact "find everything for Marcie/Gab" task was already run once before

On 2026-07-26, in a session called **"Compiling KQL queries from security
investigation,"** you asked me this near-identical question ("I feel there
was over 200, do a really deep search"). That session:

- Searched 11+ distinct past conversations
- Recovered **36 files** with real verbatim content (not 200+ — that count
  was confirmed not achievable because many queries were typed inline
  during live investigation rather than saved as named files)
- Produced two zips: `IR-2026-004_Recovered_KQL.zip` (36 files) and
  `skill_rebuild_omnia-security-ir_kql.zip` (meant to be copied into
  `/mnt/skills/user/omnia-security-ir/references/kql/`)
- Explicitly flagged it could NOT fully reconstruct two files even after
  the deep pass: `IR-2026-004_DomainCompromise_Verification.kql` (a Parts
  0-10 canonical library) and `OMNIA_TeamsHelpdeskImpersonation_Hunt_FINAL.kql`
  (the full 10-stage query that originally caught this campaign)

**Neither of those two zips exists anymore.** Session working directories
don't persist between conversations — only what actually got copied into
your project files or the skill folder survives. Since the skill folder
copy required manual action on your end ("I don't have write access...
has to land on your end"), and the current `/mnt/skills/user/omnia-security-ir/
references/kql/` folder only has the same 11 files as the original vishing
library (not 36+), **that recovery work appears to have been lost** — the
zips were generated but likely never downloaded/re-uploaded back into the
project or skill folder.

That prior session's own inventory table (session-by-session breakdown,
estimated ~130-165 total identifiable queries across all IR-2026-004 work)
is reproduced below since it's the most complete map that exists of the
true scope:

| # | Session | Date | Contents | Est. queries |
|---|---|---|---|---|
| 1 | "This f" investigation | Jul 22 | Vaelix beacon (26-port scan), 71-host lateral recon, Ditto/labe.ls checks | ~10-15 |
| 2 | "Debugging vishing-to-execution correlation" | Jul 22 | Teams-call-to-execution join iterative rebuild | ~6-8 |
| 3 | "Wacatac malware detection and remediation" | Jul 22-26 | Final IR report v3.0, **15 Sentinel detection rules** | ~15-20 |
| 4 | "Teams cross-tenant attack detection query" | — | vishing-kql-library build (8 files) — **now recovered in skill_library/** | 8+ |
| 5 | "Query for unapproved RMM records" | — | LOLRMM install + execution standalone rules | 3 |
| 6 | "Sentinel detection rules for missed alerts" | Jul 23 | Recovered 3 rules + fixed LOLRMM rule | 4 |
| 7 | "Security investigation checklist" | Jul 24 | ~30 query runs, 4 call windows — **partially recovered in section 7 above** | ~30+ |
| 8 | "Active Directory hardening and attack paths" | Jul 26 | DCSync ACL audit, Kerberoasting/AS-REP/RBCD gaps | ~5 |
| 9 | "Chaos ransomware group attribution" | Jul 26 | `IR-2026-004_DomainCompromise_Verification.kql` Parts 0-10 + 6-file detection-rules folder | ~16-20 |
| 10 | "KQL query comparison and differences" | Jul 26 | CS's 4 rules vs. tuned rules (entity-mapping fixes) | 8 |
| 11 | Project files | — | Already in this zip (skill_library/, project_files/, extracted_from_docs/) | 90 |
| 12 | "Detecting localgroup and password reset commands" | Jul 28 | Recovered above — localgroup/password/coercion queries | ~6 |
| 13 | "Malware autopsy" (Autopsy forensics) | Jul 28 | Not KQL — disk forensics file-path guidance, no queries | 0 |
| 14 | "PowerShell process query during call windows" | Jul 27 | IOC datatable + ThreatIntelIndicators join pattern | ~4 |

**Updated honest total: roughly 105 queries recovered verbatim across this
whole zip (sections 1-8), against a true universe of ~140-175+ that were
built across the incident** (the true universe grew too, since section 8
covers queries built in sessions from 07-27 through today that didn't
exist yet when the 07-26 recovery attempt estimated ~130-165). The gap is
still concentrated in the same three places: the 15 Sentinel detection
rules from the Wacatac session, the Parts 0-10 canonical verification
library, and the OMNIA_TeamsHelpdeskImpersonation_Hunt_FINAL 10-stage
query — all three confirmed built and used, but not fully recoverable
verbatim from search snippets across any of the three passes (07-26,
initial 07-28 pass, this follow-up pass).

**If these three are the ones you actually need**, the fastest real path
isn't more searching — it's telling me to open those three source
conversations directly by name/date so I can pull from them one at a time
rather than via keyword search, or, if you still have the two zips from
the 07-26 session anywhere (Downloads folder, email, etc.), re-uploading
them here would restore the full 36-file set instantly.

## 8. past_chats/IR-2026-004_recent_20260727-28/ — [FULL, 4 files/~14 queries] — NEW since 07-26
These are queries built in sessions that happened AFTER the 07-26 "Compiling
KQL queries" recovery attempt — so they were never part of that 36-file
count and are genuinely new material this pass caught:
- FortiGate/CommonSecurityLog SMB-NetBIOS-RPC blocked-traffic check (6 queries:
  schema validation, full traffic view, filtered-to-blocked, plus 2 scoped
  to Marcie's device/IP specifically)
- All-4-call-windows cmd.exe/powershell.exe/explorer.exe execution query
  (datatable-driven, covers both victims across all sessions in one query)
- All-4-call-windows file-drop staging-path query (same datatable pattern)
- Reusable IOC datatable + CIDR-range correlation against DeviceNetworkEvents
  and ThreatIntelIndicators (the full up-to-date IOC list with role/status
  metadata, including the two Russian Teams-vishing calling ranges)

---

## Bottom line

**Recovered verbatim and included in this zip: ~90 individual KQL statements**
across 76+ files (11 skill files, 1 project file, 54 doc-embedded blocks, 10
hunting-package queries, 6 insider-risk/AiTM queries, 3 standalone recovered
queries = the full FULL-status list above).

**Confirmed to exist but not recoverable verbatim: roughly 40-50 more**,
mostly because the source conversation only persists as an AI summary rather
than a raw transcript. I did not reconstruct these from the summaries and
label them as "recovered" — that would hand you queries that look like yours
but may have drifted in field names or logic, which is worse than not having
them.

If you want any of the NAMED ONLY queries rebuilt from scratch (not
recovered — rebuilt, clearly labeled as such), tell me which ones and I'll
write them fresh against your current schema. That's a different and
explicitly-labeled deliverable from what's in this zip.
