# War Cyber Claims Tracker — Gulf Targets

**Purpose:** Track hacktivist and state-linked claims of cyber attacks against
Gulf targets during the 2026 conflict, and separate **claims** from
**verified evidence**. Most wartime hacktivism is exaggeration; this tracker
exists to document what actually holds up.

**Version:** 1.0 — 2026-08-04

---

## Verification tiers (strict — no middle ground)

| Tier | Meaning | Rule |
|---|---|---|
| `CLAIMED` | A group asserted an attack. No independent technical evidence. | Default state of every entry. |
| `VERIFIED` | Independent technical evidence confirms impact (see standards below). | Requires the evidence link column filled. |
| `DEBUNKED` | Evidence contradicts the claim (target stayed up, data is recycled, etc.). | Requires the evidence link column filled. |

A claim NEVER moves from `CLAIMED` to `VERIFIED` on the strength of a second
claim, a screenshot from the claimant, or media repetition. Technical
evidence only.

## Verification standards per attack type

- **DDoS:** Target unreachable (or severely degraded) in `verify_claim.py`
  multi-check run during the claimed window, PLUS one independent vantage
  point (e.g. check-host.net result). A single failed fetch is not evidence.
- **Defacement:** Live observation of the defaced page + archived copy
  (web.archive.org) URL in the evidence column.
- **Breach / data leak:** Do NOT download or repost personal data. Verify
  structure only (does the sample schema plausibly match the victim?) and
  note recyclability (old breach re-branded = `DEBUNKED` if proven).
- **Malware campaign:** Sample hash confirmed malicious on VirusTotal or
  listed in URLhaus/MalwareBazaar; full analysis goes into a numbered
  report (005+), not here.

## Redaction rule (binding — same as the main reports)

Victim organizations are recorded by codename (`SA-BANK-01`, `QA-GOV-01`...)
until the incident is public knowledge from the victim itself or a major
outlet. Run `python3 check_redaction.py` from the repo root before every
push — a redacted identity must not leak through a raw log file (this rule
was added after two real leaks; see report 003 correction log).

## Files

- `claims_log.csv` — the ledger. One row per claim. Append-only: corrections
  are new rows or a status change with a note, never silent edits.
- `verify_claim.py` — availability checker for DDoS claims (see header).
- `groups.md` — watchlist of groups currently claiming Gulf operations.

## Publication rule

Only `VERIFIED` items may feed reports, tweets, or IOC releases. `CLAIMED`
items stay in the ledger as context. Blocking recommendations must never
include low-confidence indicators (house rule from reports 001-004).
