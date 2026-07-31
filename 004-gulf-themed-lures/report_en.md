---
Report ID:        CTI-2026-004
Title:            Gulf-Themed Lures on Foreign Infrastructure
Analyst:          Mijlad Al-Subaie (@screem500)
Published:        2026-07-25
Last Updated:     2026-08-01 (v1.1 — analytical corrections and redaction fix)
Classification:   TLP:CLEAR
Confidence:       Moderate overall; see Key Judgments for per-judgment confidence
Status:           Reported - GitHub T&S receipt confirmed; national CERTs notified
Redactions:       QA-HOST-01 (compromised victim domain)
---

# Investigation 004: Gulf-Themed Lures — Regional Decoy Names on Foreign Infrastructure

**Report date:** July 25, 2026
**Analyst:** Mijlad Al-Subaie — CEH · CHFI | X: @Al7lhh223 https://x.com/Al7lhh223 · GitHub: screem500 https://github.com/screem500
**Status:** Defensive analysis — cleared for publication
**Reporting:** On 2026-07-25: both live SmartLoader-MaaS repositories reported to GitHub Trust & Safety (receipt confirmed), and the relevant authorities in Oman and Qatar notified of the indicators using their country-themed lures (omani-disputes.com / QA-HOST-01 [REDACTED])
**Methodology:** Open-source monitoring (URLhaus, ThreatFox) + platform intelligence (WHOIS/RDAP, GitHub API) — no sample execution
**Related:** Investigation 001 (ClearFake-iran) · Investigation 002 (Kikimora/QatarRAT) · Investigation 003 (UAE ClearFake Live)
**Redaction:** QA-HOST-01 is a likely-compromised victim domain — identity withheld per the Responsible Disclosure Policy; reported to Qatar's national CERT and the registrar (PDR) on 2026-07-25

---

## 1. Executive Summary

Daily pipeline monitoring surfaced **five independent indicators** over six weeks, of which **only two carry explicit Gulf naming** (Qatar, Oman), a third is a low-confidence substring match (shaggulf-sold.xyz), while analysis showed the fourth (gulfbreezervrentals.com) is named after a business in Gulf Breeze, Florida, and is unrelated to the Gulf region. All actual infrastructure sits outside the region (Germany, United States). The analysis distinguishes two patterns:

- **Compromised legitimate domains** with Gulf branding (`QA-HOST-01 [REDACTED]` — registered 2023)
- **Purpose-registered campaign domains** (`omani-disputes.com` — registered 5 weeks before first observed use)

Analytical takeaway: Gulf-themed naming is **not sufficient evidence of exclusive Gulf targeting** (as Investigation 002 demonstrated for QatarRAT), but in the two confirmed cases (Qatar, Oman) it shows deliberate adoption of regional identity as a lure — warranting continuous monitoring and coordinated reporting.

---

## 2. The Five Indicators

| # | Indicator | Malware | Gulf Theme | Status at Observation |
|---|-----------|---------|-----------|----------------------|
| 1 | `QA-HOST-01 [REDACTED]/sonic.exe` + `/fallacy001.exe` | PureLogsStealer | Qatar | offline |
| 2 | `omani-disputes.com/txt/adkbjdd.txt` | reverse base64 loader | Oman | offline |
| 3 | `jnhygwu4.gulfbreezervrentals.com` | ClearFake (macOS) | N/A — named after Gulf Breeze, Florida (likely compromised US site) | offline |
| 4 | `shaggulf-sold.xyz/avast_update` | Potemkin Loader | Gulf-wide? (low confidence — substring match only) | offline |
| 5 | Two GitHub accounts (`rsaudio`, `Alpacareticulitermeslucifugus340`) | SmartLoader-MaaS | — | **online** |

---

## 3. Infrastructure Analysis

### 3.1 QA-HOST-01 [REDACTED] — Compromised Legitimate Domain (medium confidence)

| Field | Value |
|-------|-------|
| Registered | 2023 (~2.5 years before the campaign) |
| Registrar | PDR Ltd. (PublicDomainRegistry) |
| Hosting | Hetzner, Germany (IP withheld — publishing it defeated the domain redaction) |
| DNSSEC | unsigned |

**Reasoning:** Domain age far predates the campaign + cheap German hosting + stealer distribution via randomly-named paths (`sonic.exe`, `fallacy001.exe`) = pattern of a compromised site abused as a distribution platform, not an attack-registered domain.

### 3.2 omani-disputes.com — Purpose-Registered for the Campaign (high confidence)

| Field | Value |
|-------|-------|
| Registered | **2026-05-29** |
| First observed use | 2026-07-05 (5 weeks later) |
| Registrar | NiceNIC International |
| Hosting | 3.144.33.123 — Amazon Technologies (AWS), United States |

**Reasoning:** The name ("Omani disputes") suggests a claims/disputes page — a classic phishing template. Recent registration + rapid weaponization + raw text-path payload (`/txt/adkbjdd.txt` serving reversed-base64 loader) = infrastructure provisioned specifically for this campaign.

### 3.3 gulfbreezervrentals.com — Link to Investigation 003

Tagged in URLhaus as `ClearFake,mac-0x68dc,macOS` — additional confirmation of what Investigation 003 documented in the field: **ClearFake is no longer Windows-only** and has expanded to macOS via fake update lures.

**Correction (2026-08-01):** The domain name does not refer to the Arabian Gulf. It reads "Gulf Breeze RV Rentals" — Gulf Breeze is a city in Florida on the Gulf of Mexico, and "RV rentals" is recreational-vehicle rental. The site is most likely a **compromised** US small business, consistent with the random subdomain (`jnhygwu4`) and ClearFake's known use of compromised legitimate sites. It is therefore excluded from the Gulf-naming count and retained only as evidence of ClearFake's macOS expansion.

### 3.4 SmartLoader-MaaS via GitHub — Live at Publication Time

Two repositories distributing malicious ZIP archives via `raw.githubusercontent.com`:

- `rsaudio/second-brain` — disguised as a "second_brain_v3.7" project
- `Alpacareticulitermeslucifugus340/rockyou_uzb` — disguised as an Uzbek password wordlist (same cover style as Kikimora-arch in Investigation 002)

**Shared pattern:** Abusing GitHub's reputation as distribution infrastructure + camouflage as legitimate-looking open-source projects.

---

## 4. Unified Timeline

| Date | Event |
|------|-------|
| 2026-05-29 | omani-disputes.com registered (NiceNIC) |
| 2026-06-22 | Two SmartLoader-MaaS payloads uploaded to GitHub |
| 2026-07-05 | omani-disputes.com serves loader (first sighting) |
| 2026-07-14 | QA-HOST-01 [REDACTED] serves PureLogsStealer (two paths, 7 minutes apart) |
| 2026-07-20 | gulfbreezervrentals.com serves ClearFake-macOS |
| 2026-07-23 | shaggulf-sold.xyz serves Potemkin |
| 2026-07-25 | Both SmartLoader-MaaS indicators still online |

---

## 5. Tactics & Techniques (MITRE ATT&CK)

Techniques observed across the five indicators. Not every technique applies to
every case; the Evidence column names the case.

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | omani-disputes.com registered 5 weeks before first use |
| Resource Development | Compromise Infrastructure: Domains | T1584.001 | QA-HOST-01 — legitimate domain registered 2023, later abused |
| Resource Development | Acquire Infrastructure: Web Services | T1583.006 | Two burner GitHub accounts hosting SmartLoader-MaaS |
| Initial Access | Drive-by Compromise | T1189 | ClearFake (macOS) on jnhygwu4.gulfbreezervrentals.com |
| Execution | User Execution: Malicious File | T1204.002 | Victims run sonic.exe / fallacy001.exe / avast_update |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Potemkin Loader delivered as "avast_update" |
| Defense Evasion | Obfuscated Files or Information | T1027 | Reverse-base64 loader at omani-disputes.com/txt/ |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | Loader decodes its payload at runtime |
| Command and Control | Ingress Tool Transfer | T1105 | SmartLoader-MaaS archives pulled from raw.githubusercontent.com |
| Credential Access | Credentials from Password Stores | T1555 | PureLogsStealer collection stage |

---

## 6. Key Judgments

- These five indicators are not one campaign. Malware families differ
  (stealer, loader, ClearFake, MaaS) and the infrastructure is distributed.
  The correct framing is a *phenomenon*, not a *campaign*.
  Confidence: **High**. Basis: distinct families and unrelated hosting across
  all five cases; no shared operator artifact was found.

- Gulf-themed naming is a lure, not proof of exclusive Gulf targeting —
  consistent with the analytical correction in Investigation 002.
  Confidence: Moderate to High. Basis: the actual infrastructure sits in
  Germany and the United States; no Gulf-specific payload content was
  observed. One initially-counted indicator (gulfbreezervrentals.com) was
  excluded on re-analysis: it is named after Gulf Breeze, Florida, not the
  Arabian Gulf.

- The recurrence of the pattern (five indicators in six weeks, two with confirmed Gulf naming) is frequent enough
  to warrant tracking as an early-warning indicator.
  Confidence: Moderate. Basis: short observation window drawn from a
  single pipeline; the rate may reflect collection bias rather than a real
  increase.

- The two SmartLoader-MaaS repositories were live at analysis time.
  Confidence: High. Basis: direct first-party retrieval; reported to
  GitHub Trust & Safety with receipt confirmed.

- QA-HOST-01 is a compromised legitimate domain rather than an
  attacker-registered one.
  Confidence: Moderate. Basis: 2023 registration date and unrelated
  legitimate content; no server-side artifact confirms the compromise vector.

### Confidence Scale

High — Multiple independent sources, or direct first-party observation.
Moderate — Consistent evidence, plausible alternatives not fully excluded.
Low — Single source or circumstantial; stated as hypothesis only.


## 7. Recommendations

| Action | Recipient | Priority |
|--------|-----------|----------|
| Report SmartLoader-MaaS repositories | GitHub Trust & Safety | 🔴 Urgent |
| Report omani-disputes.com | Oman National CERT (mCERT) + NiceNIC abuse | 🟠 High |
| Report QA-HOST-01 [REDACTED] | Qatar National Cyber Security Agency + PDR abuse | 🟠 High |
| Add indicators to local detection rules | Gulf SOC teams | 🟡 Follow-up |

---

## 8. IOC Appendix

See the attached `iocs_004_gulf_lures.txt` — includes domains, full URLs, IP addresses, and URLhaus references for each indicator.

---

## 📋 Correction Log (2026-08-01 — v1.1)

- Reclassified `gulfbreezervrentals.com`: the name belongs to an RV-rental business in Gulf Breeze, Florida — not the Arabian Gulf; removed from the Gulf-naming count.
- Withheld QA-HOST-01's IP address and URLhaus IDs — publishing them alongside the redaction made the domain identifiable; removed per the Responsible Disclosure Policy.
- Aligned `shaggulf-sold.xyz` to low confidence across the table and summary (substring match only).
- Corrected the T1105 row: retrieval from raw.githubusercontent.com, not GitHub releases (releases relate to Investigation 002).

---

## ⚠️ Disclaimer

Purely defensive analysis. All indicators sourced from open threat feeds (URLhaus, ThreatFox) and public registration data. No malicious samples were executed or downloaded. Confidence levels are stated explicitly for each judgment.
