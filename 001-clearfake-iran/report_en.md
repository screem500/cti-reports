---
Report ID:        CTI-2026-001
Title:            ClearFake on Compromised Iranian Infrastructure
Analyst:          Mijlad Al-Subaie (@screem500)
Published:        2026-07-21
Last Updated:     2026-08-01 (v1.1 — figure consistency corrections)
Classification:   TLP:CLEAR
Confidence:       High on the ClearFake attribution; see Key Judgments for per-judgment confidence
Status:           Published - infrastructure monitoring ongoing
Redactions:       UAE-HOST-01 (compromised third-party site) redacted pending remediation; attacker infrastructure published in full
---

# Campaign Analysis: ClearFake on Compromised Iranian Infrastructure

Report date: 2026-07-21
Analyst: Mijlad Al-Subaie - CEH · CHFI | X: [@Al7lhh223](https://x.com/Al7lhh223) · GitHub: [screem500](https://github.com/screem500)
Status: Defensive analysis — cleared for publication

---

## Key Judgments

- An active ClearFake campaign is distributing fake browser-update lures from 37 compromised Iranian (.ir) domains serving 58 malicious URLs.
  Confidence: **High**. Basis: ThreatFox classification at 100% confidence, corroborated by URLhaus feed data.

- The Iranian domains are compromised victims, not willing participants.
  Confidence: **High**. Basis: all are legitimate civilian sites (sports, health, education) with unrelated primary content.

- The compromise pattern is automated mass exploitation, most likely of outdated WordPress installations.
  Confidence: **Moderate**. Basis: long-tail distribution (29 domains with a single URL each) and subdomain-generation pattern; no server-side artifacts were obtained to confirm the entry vector.

- The degraded defensive posture of Iranian civilian web assets is linked to current conflict conditions and the extended internet shutdown.
  Confidence: **Low to Moderate**. Basis: circumstantial timing only; stated as a hypothesis, not a finding.

- The Cobalt Strike C2 and the Vidar distribution on UAE-HOST-01 belong to the same broader crimeware ecosystem but are separate findings, not confirmed to be the same operator.
  Confidence: **Low** on operator linkage. Basis: feed co-occurrence only.

### Confidence Scale

High — Multiple independent sources, or direct first-party observation.
Moderate — Consistent evidence, plausible alternatives not fully excluded.
Low — Single source or circumstantial; stated as hypothesis only.

---

## 1. Executive Summary

This analysis documents an active ClearFake campaign (fake browser update lures) hosted on 37 compromised Iranian (.ir) domains serving 58 malicious distribution URLs, alongside indicators of a broader criminal infrastructure including an active Cobalt Strike C2 on an Iranian domain and a compromised UAE-based website distributing the Vidar stealer. Notably, the abused Iranian infrastructure is entirely civilian (sports, health, and education websites), indicating a degraded defensive posture of Iranian civilian web assets amid the ongoing conflict and the country's extended internet shutdown.

**Update (2026-07-24):** Campaign remains active on the same infrastructure (59 active URLs), now with UUID tracking parameters (`?ublib=`) appended to links — likely per-victim tracking, confirming active campaign management.

---

## 2. Attribution

- **Malware family:** ClearFake — a JavaScript-based infection chain presenting fake "browser update" prompts to trick victims into downloading a payload.
- **Operator profile:** Crimeware ecosystem, not a state actor.
- **Key point:** The Iranian domains are compromised victims, not willing participants — legitimate civilian sites abused as distribution platforms.
- **Confidence:** High on ClearFake attribution (confirmed in ThreatFox with 100% confidence); moderate on linking the degraded defensive posture to current conflict conditions. See Key Judgments above.

---

## 3. Timeline

| Date | Event | Source |
|------|-------|--------|
| 2026-06-05 | Cobalt Strike C2 observed at ns1.newchatsits.ir | ThreatFox |
| 2026-07-10 | Ongoing ClearFake activity on varzeshlife.ir | ThreatFox |
| 2026-07-17/18 | Peak of distribution URLs on Iranian domains | URLhaus |
| 2026-07-19/20 | Additional infections; compromised UAE site (Vidar) | URLhaus / ThreatFox |
| 2026-07-21 | Cobalt Strike C2 still active (last seen) | ThreatFox |
| 2026-07-24 | Campaign still active; UUID tracking parameters observed | URLhaus |

---

## 4. Targeting

- **End victims:** Ordinary users on both Windows and macOS (note tags `win-0x4679` and `mac-0x68dc`).
- **Abused platforms — Iranian civilian sites by category:**
  - Sports: varzeshlife, 20sport, goaliran, futboliran, gamesport, elitesport, likesport, lionsport, itsport, footbalpersian
  - Health: medsalamat, salamatyari, healthvarzesh
  - Education: eduprof, persianeducation, farsibeenglish, ketabworld
  - Services & commerce: novin-gps, podcastshop, radmanwear, iranmotorplus, others
- **Gulf extension:** UAE-HOST-01 (UAE) — Vidar distribution via ClickFix + EtherHiding. Identifier redacted pending remediation; see Redactions in the header.

---

## 5. Tactics & Techniques (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Resource Development | Compromise Infrastructure | T1584 | Legitimate sites abused for distribution |
| Initial Access | Drive-by Compromise | T1189 | Infection of compromised-site visitors |
| Execution | User Execution: Malicious File | T1204.002 | Victim lured into downloading "browser update" |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | `js.clearfake` loader |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | ClickFix — victim pastes command (Gulf case) |
| Defense Evasion | Impersonation | T1656 | Fake browser update pages |
| Defense Evasion | Obfuscated Files or Information | T1027 | Obfuscated JS loader; EtherHiding payload concealment |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | ClearFake C2 over HTTP(S); Cobalt Strike beacon at ns1.newchatsits.ir |

---

## 6. Indicators of Compromise (IOCs)

Machine-readable indicators: [`iocs_001_clearfake_iran_stix.json`](iocs_001_clearfake_iran_stix.json) (STIX 2.1)
Human-readable list: [`iocs_001_clearfake_iran.txt`](iocs_001_clearfake_iran.txt)

Attacker-controlled infrastructure is published in full. Compromised third-party hosts outside the Iranian set are redacted per the repository disclosure policy.

### 6.1 Compromised Iranian domains

Distribution by parent domain (37 domains total, 58 URLs):

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
| 29 other domains | 1 each | Mixed (health, education, commerce) |

**Analytic note:** 19% of URLs concentrate on a single domain (varzeshlife.ir), suggesting deep compromise with broad access, while the long tail (29 domains with a single hit) reflects automated mass exploitation — most likely via outdated WordPress plugins.

### 6.2 High-value indicators

| Indicator | Type | Description | Status |
|-----------|------|-------------|--------|
| ns1.newchatsits.ir | domain | Cobalt Strike C2 | Active (last seen 2026-07-21) |
| UAE-HOST-01 | domain | Vidar distribution (ClickFix/EtherHiding) | Compromised — REDACTED pending remediation |
| `*.<random>.varzeshlife.ir` | domain | ClearFake distribution | Rotating |

### 6.3 Contemporaneous feed observations (MalwareBazaar — no established link)

- AgentTesla as `Purchase Order No. MP.S.006025-08524.js` (business phishing)
- RemcosRAT as `Invoice_details_for_confirmation_scan_0715202600.vbe`
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
- Never paste a command into PowerShell or Terminal at a website's request (ClickFix)

**For defenders (SOC):**
- Block listed IOCs at DNS/proxy level
- Monitor for random-pattern subdomain creation on managed domains (compromise indicator)
- Alert on the listed indicators (see §6), and on random-pattern subdomain creation on managed domains
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

*Disclaimer: This analysis is for defensive and research purposes. Indicators are drawn from open-source threat feeds and first-party analysis. Samples are never executed.*
