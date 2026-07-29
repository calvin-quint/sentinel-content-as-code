# Vishing KQL Library — IR-2026-004
Rebuilt index for `omnia-security-ir/references/kql/`. This folder was found
empty during a July 26, 2026 audit — these files restore what memory says
should be here, recovered from past chat history where possible.

| File | Source | Status |
|---|---|---|
| 01_DCSync_Detection_FINAL.kql | AD hardening + Chaos ransomware sessions | Corrected version — supersedes any older DCSync draft with hqdc03 in scope |
| 02_DCSync_LogonSource_Pivot.kql | Chaos ransomware session | Complete |
| 03_Egress_Filtering_Gap_Check.kql | Chaos ransomware session | Complete — CRITICAL finding, DCs reaching public internet |
| 04_DC_ShareAccess_And_PrivilegedChange_Checks.kql | Chaos ransomware session | Complete — Bookmark Checklist 11b/11c |
| 01_LOLRMM_Fixed_Join_And_SanityCheck.kql | Directory whitelisting + Sentinel rules sessions | Complete, both bug fixes applied |
| 02_LOLRMM_Process_Detection_With_Exclusions.kql | Sentinel rules session | Complete |
| 03_RMM_Launch_Recon_Burst_Correlation.kql | Chaos ransomware repo-build session | Complete |
| 01_TeamsHelpdeskImpersonation_Hunt_RecoveredStages.kql | Teams cross-tenant attack session | PARTIAL — this is the query that caught IR-2026-004; full 10-stage assembly not fully recovered, see notes in file |
| 01_Vaelix_Port_Overlap_Check.kql | Wacatac session | Complete |
| 02_Curl_OneShot_Dropper_Confirmation.kql | Wacatac session | Complete |
| 03_Vaelix_Ditto_Combined_Network_Window.kql | Wacatac session | Complete |

## Known gap
The full `OMNIA_TeamsHelpdeskImpersonation_Hunt_FINAL.kql` (all 10 stages)
and `IR-2026-004_DomainCompromise_Verification.kql` (Parts 0-10) were
confirmed built in past sessions but couldn't be fully reconstructed from
search snippets alone. If you want these byte-perfect, the fastest path is
opening those two specific past chats directly (search: "Teams cross-tenant
attack detection query" and "Chaos ransomware group attribution") and having
me pull the full file content from within that conversation.

## To install
Copy the .kql files in this same zip folder into
`/mnt/skills/user/omnia-security-ir/references/kql/` — I don't have write
access to that path from here, so this has to be dropped in on your end (or
tell me to do it next time that directory is writable/if you re-upload it
as a project file).
