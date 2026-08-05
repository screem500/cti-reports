# Investigation 005 (in progress): The Gulf in the 2026 Cyber War — Claims vs. Evidence

**Status:** Data collection phase — NOT for publication yet.
**Started:** 2026-08-04
**Question:** During the 2026 conflict, what actually touched the Gulf in
cyberspace — and how much of the public noise was claim rather than evidence?

## Why this report exists

February–April 2026 saw an intense documented wave of cyber activity tied to
the war (vendor-published figures: thousands of attacks, dozens of
Iran-aligned groups, organized hacktivist target lists against Gulf states).
By August 2026 the visible noise has faded. Nobody has documented the fade
with data. This report will — from first-party daily collection, with the
same discipline as Investigations 001–004:

- Every claim is `CLAIMED`, `VERIFIED`, or `DEBUNKED`. No middle tier.
- Negative results are results. A quiet week is published as a quiet week.
- Attribution only as vendor-attributed ("per Kaspersky / Check Point"),
  never as our own claim.

## Planned structure

1. Executive summary (written last)
2. Scope and method (daily pipeline, verification tiers)
3. The hot phase (Feb–Apr 2026): what vendors documented
4. The fade (May–Aug 2026): what our own daily collection shows
5. The claims ledger: counts by group, type, verdict
6. Context: IRGC-linked espionage active during/after the war
   (Mirage Kitten / Nimbus Manticore / UNC1549) — see context_mirage_kitten.md
7. Verified incidents touching the Gulf (from Investigations 001–004 and
   any new verified item)
8. Key Judgments (per-judgment confidence)
9. Correction log

## Files

- `daily_log.md` — the collection diary. One dated entry per scan day.
  This is the evidence base of the whole report.
- `context_mirage_kitten.md` — cited context paragraph (AR/EN).
- Report drafts (`report_ar.md`, `report_en.md`) will be created when the
  collection window closes (~2 weeks of data).

## Daily routine (5 minutes)

1. Run the Gulf filter on the URLhaus recent feed (script used since
   Investigation 001; run from Kali or ask in chat).
2. Note any hacktivist claim touching the Gulf (Telegram/X mirrors).
3. Write one dated line in `daily_log.md` — even if "quiet".
4. Before any push: `python3 check_redaction.py` from repo root.
