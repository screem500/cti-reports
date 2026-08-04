# Group Watchlist — Gulf-claiming actors (2026 conflict)

Living list. Add groups as they appear; remove after 30 days of silence.
Sources: public reporting (SOCRadar, Unit42, Flashpoint) — see claims_log.csv.
Updated: 2026-08-04 (v1.1 — added 5 groups + channel discovery methods)

## Watchlist

| Group | Profile per public reporting | Gulf activity claimed | Notes |
|---|---|---|---|
| APTIran | Pro-Iran hacktivist, most active during current conflict per Flashpoint | Regional gov/private targets | Top priority to monitor |
| DieNet | Pro-Iran DDoS crew | Target lists: SA/QA/BH/AE/KW banks, airports, gov portals | Publishes structured target lists — easy to collect, rarely verified |
| Handala | Iran-linked hack-and-leak persona (FBI-identified) | Claimed breach of major Saudi energy firm | Distributes wiper malware via links — never click channel content |
| 313 Team | Pro-Iran hacktivist | Kuwaiti government sites | DDoS/defacement claims |
| Cyber Toufan | Pro-Iran collective | Regional targets | Monitor for Gulf-specific claims |
| Cyber Support Front | Pro-Iran collective | Regional targets | Claimed activity in 2026-03/04 |
| Iranian Avenger | Pro-Iran hacktivist | Regional targets | Claimed activity in 2026-03/04 |
| BaqiyatLock | Ransomware crew w/ ideological recruitment | Offers free membership for attacking Israeli-linked targets | Watch for Gulf spillover |

## Channel discovery (channels get banned constantly — no permanent links)

1. **Telegram global search:** search group names directly (e.g. "DieNet",
   "APTIran"). Official channels show large subscriber counts and
   continuous post history. Beware copycats.
2. **Allied channels re-share new official channels after bans** (documented
   pattern). Known DieNet allies: Mr Hamza, LazaGrad Hack, Sylhet Gang-SG.
   Handala promotes alternatives via its sites and allied channels after
   seizures.
3. **External aggregators (no Telegram needed):** tgstat.com channel search;
   vx-underground on X; SOCRadar / Flashpoint / Unit42 blog updates.

## Safety rules (non-negotiable)

- Use a SEPARATE research Telegram account, never a personal one.
- Watch only: no replies, no reactions, no clicking links or files posted
  in channels (Handala distributes destructive wipers; Telegram has been
  used as C2 infrastructure per FBI reporting).
- Everything seen = CLAIMED until verified per README.md standards.

## Collection routine (daily, ~15 min)

1. Skim each group's public channel for new Gulf claims.
2. Log EVERY Gulf claim in `claims_log.csv` as `CLAIMED` — even obvious noise
   (the ledger's value is the full denominator).
3. Pick at most 1–2 claims worth verifying that day; run the matching
   standard from README.md. Evidence beats volume.
4. Status changes only with an evidence link. No exceptions.
