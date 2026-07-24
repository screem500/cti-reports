# Campaign Analysis: ClearFake on Compromised Iranian Infrastructure

**Report date:** July 21, 2026
**Analyst:** Mijlad Al-Subaie - CEH · CHFI | X: @Al7lhh223 https://x.com/Al7lhh223 · GitHub: screem500 https://github.com/screem500
**Status:** Defensive analysis — cleared for publication

---

## 1. Executive Summary

This analysis documents an active **ClearFake** campaign (fake browser update lures) hosted on **35 compromised Iranian (.ir) domains** serving **58 malicious distribution URLs**, alongside indicators of a broader criminal infrastructure including an active **Cobalt Strike C2** on an Iranian domain and a compromised **UAE-based website** distributing the **Vidar** stealer. Notably, the abused Iranian infrastructure is entirely civilian (sports, health, and education websites), indicating a degraded defensive posture of Iranian civilian web assets amid the ongoing conflict and the country's extended internet shutdown.


📡 Update (2026-07-24): Campaign remains active on the same infrastructure (59 active URLs), now with UUID tracking parameters (?ublib=) appended to links — likely per-victim tracking, confirming active campaign management.

---

## 2. Attribution

- **Malware family:** ClearFake — a JavaScript-based infection chain presenting fake "browser update" prompts to trick victims into downloading a payload.
- **Operator profile:** Crimeware ecosystem, not a state actor.
- **Key point:** The Iranian domains are **compromised victims**, not willing participants — legitimate civilian sites abused as distribution platforms.
- **Confidence:** High on ClearFake attribution (confirmed in ThreatFox with 100% confidence); moderate on linking the degraded defensive posture to current conflict conditions.

---

## 3. Timeline

| Date | Event | Source |
|------|-------|--------|
| 2026-06-05 | Cobalt Strike C2 observed at ns1.newchatsits.ir | ThreatFox |
| 2026-07-10 | Ongoing ClearFake activity on varzeshlife.ir | ThreatFox |
| 2026-07-17/18 | Peak of distribution URLs on Iranian domains | URLhaus |
| 2026-07-19/20 | Additional infections; compromised UAE site (Vidar) | URLhaus / ThreatFox |
| 2026-07-21 | Cobalt Strike C2 still active (last seen) | ThreatFox |

---

## 4. Targeting

- **End victims:** Ordinary users on both **Windows and macOS** (note tags win-0x4679 and mac-0x68dc).
- **Abused platforms — Iranian civilian sites by category:**
  - Sports: varzeshlife, 20sport, goaliran, futboliran, gamesport, elitesport, likesport, lionsport, itsport, footbalpersian
  - Health: medsalamat, salamatyari, healthvarzesh
  - Education: eduprof, persianeducation, farsibeenglish, ketabworld
  - Services & commerce: novin-gps, podcastshop, radmanwear, iranmotorplus, others
- **Gulf extension:** adminbyrequest.UAE-HOST-01.ae (UAE) — Vidar distribution via ClickFix + EtherHiding.

---

## 5. Tactics & Techniques (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Drive-by Compromise | T1189 | Infection of compromised-site visitors |
| Initial Access | Compromise Infrastructure | T1584 | Legitimate sites abused for distribution |
| Execution | User Execution | T1204 | Victim lured into downloading "browser update" |
| Execution | JavaScript | T1059.007 | js.clearfake |
| Defense Evasion | Impersonation | T1656 | Fake browser update pages |
| C2 (separate case) | Web Protocols (Beacon) | T1071 | ns1.newchatsits.ir |
| Delivery (Gulf case) | ClickFix + EtherHiding | T1204 / T1027 | Victim pastes PowerShell; payload hidden on blockchain |

---

## 6. Indicators of Compromise (IOCs)

### 6.1 Compromised Iranian domains (full list in domains_ir.txt)
Distribution by parent domain (35 domains total, 58 URLs):

| Domain | Malicious subdomains | Category |
|--------|---------------------|----------|
| varzeshlife.ir | 11 | Sports — most abused |
| elitesport.ir | 4 | Sports |
| sargarminovin.ir | 3 | General |
| beshnoinja.ir | 3 | Sports/fitness |
| marjaevakil.ir | 2 | Services |
| footbalpersian.ir | 2 | Sports |
| fiorentini.ir | 2 | General |
| 20sport.ir | 2 | Sports |
| 27 other domains | 1 each | Mixed (health, education, commerce) |

**Analytic note:** 19% of URLs concentrate on a single domain (varzeshlife.ir) suggesting deep compromise with broad access, while the long tail (26 domains with a single hit) reflects automated mass exploitation — most likely via outdated WordPress plugins.

### 6.2 High-value indicators
| Indicator | Type | Description | Status |
|-----------|------|-------------|--------|
| ns1.newchatsits.ir | domain | Cobalt Strike C2 | Active (last seen 2026-07-21) |
| adminbyrequest.UAE-HOST-01.ae | URL | Vidar distribution (ClickFix/EtherHiding) | Compromised |
| *.<random>.varzeshlife.ir | domain | ClearFake distribution | Rotating |
| 45.138.16.162:4321 | ip:port | AdaptixC2 | Active |

### 6.3 Related samples (MalwareBazaar)
- AgentTesla as "Purchase Order No. MP.S.006025-08524.js" (business phishing)
- RemcosRAT as "Invoice_details_for_confirmation_scan_0715202600.vbe"
- Multi-architecture Mirai samples (mips, sh4, i686, m68k, x86_64) — active IoT botnet

---

## 7. Tooling & Malware

| Tool | Role |
|------|------|
| ClearFake (JS) | Initial infection chain via fake updates |
| Vidar | Information stealer (passwords, wallets, sessions) |
| Cobalt Strike | Post-compromise C2 |
| ClickFix | Social-engineering lure (paste-it-yourself command) |
| EtherHiding | Payload concealment in blockchain smart contracts |

---

## 8. Defensive Recommendations

**For end users:**
- No legitimate browser update ever arrives via a webpage — updates happen inside the browser only
- Never paste a command into PowerShell/Terminal at a website's request (ClickFix)

**For defenders (SOC):**
- Block listed IOCs at DNS/proxy level
- Monitor for random-pattern subdomain creation on managed domains (compromise indicator)
- Alert on unexpected outbound connections to .ir domains during this period
- Include macOS endpoints in scope — this campaign is not Windows-only

**For website owners (lessons learned):**
- Dominant pattern: outdated WordPress → compromise → ClearFake injection
- Mandatory plugin updates + WAF + file-integrity monitoring

**Reporting & takedown:**
- Affected domains resolve behind Cloudflare — report the malicious URLs via cloudflare.com/abuse
- Report the most-abused domains (varzeshlife.ir, elitesport.ir) to IRNIC via whois.nic.ir

---

## 9. Sources

1. URLhaus (abuse.ch) — malicious URL feed, 2026-07-20
2. ThreatFox (abuse.ch) — ClearFake / Cobalt Strike / Vidar indicators, 2026-07-20/21
3. MalwareBazaar (abuse.ch) — malware samples
4. CISA Known Exploited Vulnerabilities Catalog

---

*Disclaimer: This analysis is for defensive and research purposes. Indicators are drawn from open-source threat feeds.*
