# Investigation 004: Gulf-Themed Lures — Regional Decoy Names on Foreign Infrastructure

**Report date:** July 25, 2026
**Analyst:** Mijlad Al-Subaie - CEH · CHFI | X: @Al7lhh223 https://x.com/Al7lhh223 · GitHub: screem500 https://github.com/screem500
**Status:** Defensive analysis - cleared for publication
**Reporting:** On 2026-07-25: both live SmartLoader-MaaS repositories reported to GitHub Trust & Safety (receipt confirmed), and the relevant authorities in Oman and Qatar notified of the indicators using their country-themed lures (omani-disputes.com / QA-HOST-01-REDACTED)
**Methodology:** Open-source monitoring (URLhaus, ThreatFox) + platform intelligence (WHOIS/RDAP, GitHub API) — no sample execution
**Related:** Investigation 001 (ClearFake-iran) · Investigation 002 (Kikimora/QatarRAT) · Investigation 003 (UAE ClearFake Live)

---

## 1. Executive Summary

Daily pipeline monitoring surfaced five independent campaigns using **explicit Gulf-themed names** (qatar, omani, gulf) as lures in domains and distribution paths - while their actual infrastructure sits entirely outside the region (Germany, United States). The analysis distinguishes two patterns:

- **Compromised legitimate domains** with Gulf branding (`QA-HOST-01-REDACTED` - registered 2023)
- **Purpose-registered campaign domains** (`omani-disputes.com` — registered 5 weeks before first observed use)

Analytical takeaway: Gulf-themed naming is **not sufficient evidence of exclusive Gulf targeting** (as Investigation 002 demonstrated for QatarRAT), but in at least two cases it shows deliberate adoption of regional identity as a lure - warranting continuous monitoring and coordinated reporting.

---

## 2. The Five Indicators

| # | Indicator | Malware | Gulf Theme | Status at Observation |
|---|-----------|---------|-----------|----------------------|
| 1 | `QA-HOST-01-REDACTED/sonic.exe` + `/fallacy001.exe` | PureLogsStealer | Qatar | offline |
| 2 | `omani-disputes.com/txt/adkbjdd.txt` | reverse base64 loader | Oman | offline |
| 3 | `jnhygwu4.gulfbreezervrentals.com` | ClearFake (macOS) | Gulf-wide | offline |
| 4 | `shaggulf-sold.xyz/avast_update` | Potemkin Loader | Gulf-wide | offline |
| 5 | Two GitHub accounts (`rsaudio`, `Alpacareticulitermeslucifugus340`) | SmartLoader-MaaS | — | **online** |

---

## 3. Infrastructure Analysis

### 3.1 QA-HOST-01-REDACTED — Compromised Legitimate Domain (medium confidence)

| Field | Value |
|-------|-------|
| Registered | 2023-09-19 (2.5 years before the campaign) |
| Registrar | PDR Ltd. (PublicDomainRegistry) |
| Hosting | 5.9.143.30 — Hetzner, Falkenstein, Germany |
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

Tagged in URLhaus as `ClearFake,mac-0x68dc,macOS` — additional confirmation of what Investigation 003 documented in the field: **ClearFake is no longer Windows-only** and has expanded to macOS via fake update lures. The domain follows a "Gulf vehicle rentals" pattern — regional commercial camouflage.

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
| 2026-07-14 | QA-HOST-01-REDACTED serves PureLogsStealer (two paths, 7 minutes apart) |
| 2026-07-20 | gulfbreezervrentals.com serves ClearFake-macOS |
| 2026-07-23 | shaggulf-sold.xyz serves Potemkin |
| 2026-07-25 | Both SmartLoader-MaaS indicators still online |

---

## 5. Analytical Judgment

1. **Not a single campaign** — malware families differ (Stealer, Loader, ClearFake, MaaS) and infrastructure is distributed. The correct framing is a *phenomenon*, not a *campaign*.
2. **Gulf naming is a lure, not targeting proof** — consistent with the analytical correction in Investigation 002. However, its recurrence (5 cases in 6 weeks) merits tracking as an early-warning indicator.
3. **Action priority:** the two live SmartLoader-MaaS indicators — immediate report to GitHub Trust & Safety.

## 6. Recommendations

| Action | Recipient | Priority |
|--------|-----------|----------|
| Report SmartLoader-MaaS repositories | GitHub Trust & Safety | 🔴 Urgent |
| Report omani-disputes.com | Oman National CERT (mCERT) + NiceNIC abuse | 🟠 High |
| Report QA-HOST-01-REDACTED | Qatar National Cyber Security Agency + PDR abuse | 🟠 High |
| Add indicators to local detection rules | Gulf SOC teams | 🟡 Follow-up |

---

## 7. IOC Appendix

See the attached `iocs_gulf_lures.txt` — includes domains, full URLs, IP addresses, and URLhaus references for each indicator.

---

## ⚠️ Disclaimer

Purely defensive analysis. All indicators sourced from open threat feeds (URLhaus, ThreatFox) and public registration data. No malicious samples were executed or downloaded. Confidence levels are stated explicitly for each judgment.
