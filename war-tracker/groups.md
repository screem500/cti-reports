# Group Watchlist — Gulf-claiming actors (2026 conflict)

Living list. Add groups as they appear; remove after 30 days of silence.
Sources: public reporting (SOCRadar, Unit42, Flashpoint) — see claims_log.csv.

| Group | Profile per public reporting | Gulf activity claimed | Notes |
|---|---|---|---|
| DieNet | Pro-Iran DDoS crew | Target lists: SA/QA/BH/AE/KW banks, airports, gov portals | Publishes structured target lists — easy to collect, rarely verified |
| Handala | Iran-linked hack-and-leak persona | Claimed breach of major Saudi energy firm | High-visibility claims; verification rate historically low |
| 313 Team | Pro-Iran hacktivist | Kuwaiti government sites | DDoS/defacement claims |
| Cyber Islamic Resistance | Pro-Iran collective | Regional gov targets | Monitor for Gulf-specific claims |

## Collection routine (daily, ~15 min)

1. Skim each group's public channel for new Gulf claims.
2. Log EVERY Gulf claim in `claims_log.csv` as `CLAIMED` — even obvious noise
   (the ledger's value is the full denominator).
3. Pick at most 1–2 claims worth verifying that day; run the matching
   standard from README.md. Evidence beats volume.
4. Status changes only with an evidence link. No exceptions.
