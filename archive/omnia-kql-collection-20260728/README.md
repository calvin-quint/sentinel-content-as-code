OMNIA KQL Collection — compiled 2026-07-28
===========================================

FOLDERS
-------

1. skill_library/
   Full contents of /mnt/skills/user/omnia-security-ir/references/kql/ (11 files)
   plus vishing-kql-library.md (index). This is your working, validated
   detection/hunting library from the IR-2026-004 vishing/ClickFix engagement.

2. project_files/
   OMNIA_UserCompromise_Correlation_Final.kql — the complete 9-stage user
   compromise correlation query (SigninLogs, EmailEvents, UrlClickEvents,
   CloudAppEvents inbox rules, AuditLogs, ThreatIntelIndicators,
   BehaviorAnalytics, OfficeActivity sends, OAuth consent/SoD flag).

3. extracted_from_docs/
   Every fenced ```kql code block pulled directly out of the three project
   markdown files that contain embedded queries:
     - IR-2026-004_Bookmark_Checklist.md (11 blocks)
     - OMNIA_IR_Playbook_v1_0.md (38 blocks)
     - OMNIA_TeamsVishingClickFix_IR_20260724_v8.md (5 blocks)
   Filenames indicate source doc + block number in original order.

4. past_chats/
   Full-text KQL recovered verbatim from past conversation transcripts
   (only possible where the chat history tool returned raw conversation
   text, not an AI-generated summary):
     - User_Invite_All_permission_audit.kql
     - DCSync_AlertEvidence_EntityType_Gotcha.kql
     - InboxRule_Forwarding_Audit_IRSOP_5.1.kql

IMPORTANT LIMITATION — please read
-----------------------------------
Your memory system stores most past conversations as AI-generated
*summaries*, not verbatim transcripts. Summaries describe what a query does
in prose but do not preserve exact KQL syntax — so that KQL cannot be
recovered exactly and is NOT included here to avoid handing you rewritten
(possibly subtly wrong) queries under the label "recovered."

Conversations found in this search that reference KQL but where I could
NOT recover literal query text (summary-only, no raw transcript available):

  - "KQL query for outgoing emails" (2026-05-12) — EmailEvents/EmailAttachmentInfo/
    OfficeActivity exfil risk-scoring query
  - "KQL query for admin consent approval" (2026-05-14) — AuditLogs approval +
    business-hours variant
  - "Detecting suspicious sign-ins and inbox rule changes" (2026-04-14) —
    SigninLogs + CloudAppEvents new-IP-then-rule-change correlation, plus a
    revised join-kind=anti / BehaviorAnalytics-enriched version
  - "KQL query for mailbox rule changes" (2026-04-14) — 3-query OfficeActivity/
    CloudAppEvents set for inbox + transport rule changes
  - "Anomalous sign-in queries and false positives" (2026-07-02) — references
    an entire ~55-query package (proactive hunting set, 6 analytics-rule
    gap-fills, service-principal sign-in tiers, 4 OOB-rule replacements)
    built across earlier sessions predating this project
  - "AiTM detection and IR playbook technical documentation" (2026-07-20) —
    two AiTM UniqueTokenIdentifier cross-IP variants (direct + 14-day
    baseline/set_difference), documented as design discussion but the full
    query text sits in a chat this search could not retrieve verbatim

If any of these are queries you still rely on, the most reliable path is
for you to re-paste them from wherever you last saved them (Jira, GitHub
repo cquint-omnia/sentinel-kql-library, Atera, ITGlue), since that's the
source of truth — chat memory is not a safe long-term store for exact syntax.

I can also go chat-by-chat and open each of the sessions above directly
(rather than relying on search snippets) to try to pull literal text if
you want me to keep digging — just say the word.
