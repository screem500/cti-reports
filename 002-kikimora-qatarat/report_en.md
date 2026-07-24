# Deep-Dive Investigation: Kikimora / QatarRAT Campaign — From Threat Feed to Operator Fingerprint

**Report date:** July 21, 2026
**Analyst:** [Your name]
**Status:** Defensive analysis — cleared for publication
**Methodology:** OSINT monitoring + static malware analysis + platform intelligence (GitHub API, RDAP, CT Logs)

---

## 1. Executive Summary

This investigation began with a single URLhaus indicator ("QatarRAT") and evolved into the full exposure of a distribution campaign active since February 2026 through a burner GitHub account (Kikimora-arch), accumulating roughly **18,000 downloads** via cracked-software lures (FL Studio, SOLIDWORKS, Steam), with specialized components including an **AVKiller** module and a RAT client. Static analysis revealed a tampered digital signature impersonating a DigiCert certificate, algorithmically-styled standby domains, and linguistic fingerprints pointing to a **Russian-speaking operator** — weakening the "Qatar-exclusive targeting" hypothesis and supporting a broad crimeware campaign that hit the Gulf among other targets.

---

## 2. Attribution

| Indicator | Meaning |
|-----------|---------|
| Handle "Kikimora" | Creature from East Slavic folklore |
| Repo "solid-pomoemy" | "pomoemy" transliterates Russian "по-моему" (in my opinion) |
| Repo descriptions | "the first repo :p" / "the second rep" — informal style |

- **Assessment:** Most likely a Russian-speaking operator within the crimeware ecosystem.
- **Confidence:** Medium (linguistic markers can be deliberately faked — False Flag).
- **Key analytic correction:** The "QatarRAT" label in threat feeds does not necessarily imply Qatar-exclusive targeting; it may reflect an analyst's naming after Qatari victims, or operator deception.

---

## 3. Timeline

| Date | Event | Source |
|------|-------|--------|
| 2026-02-24 16:02 | Kikimora-arch account created | GitHub API |
| 2026-02-24 16:03 | First repo solid-pomoemy created (empty decoy) | GitHub API |
| 2026-02-24 16:18 | Second repo solid-doodle created | GitHub API |
| 2026-02-24 16:24 | Release v1.00.2 published with 10 malicious files | GitHub API |
| 2026-06-27 | JavaChecker.exe flagged in threat feeds (QatarRAT) | URLhaus |
| 2026-07-21 | File still downloadable (online) | URLhaus |

**Note:** Account, two repos, and payload release within 22 minutes = pre-staged single-purpose burner account.

---

## 4. Indicators of Compromise (IOCs)

### 4.1 Core infrastructure
| Indicator | Type | Details |
|-----------|------|---------|
| github.com/Kikimora-arch/solid-doodle | account/repo | Primary distribution platform — active |
| github.com/Kikimora-arch/solid-pomoemy | repo | Empty decoy |
| fe566ca92d40914438c7ce3157a6a0936ac7be94e71e6c37b95ac84177511874 | SHA256 | JavaChecker.exe |

### 4.2 Release v1.00.2 payloads (10 files)
| File | Size | Downloads | Assessed role |
|------|------|-----------|----------------|
| kikikmoralibrary.exe | 1.4MB | **11,984** | Most distributed payload |
| JavaChecker.exe | 2.9MB | **4,515** | QatarRAT (this investigation's sample) |
| SolidLite.exe | 278KB | 882 | Supporting payload |
| solidbeta.exe | 33MB | 621 | Payload sized as legitimate software |
| Flstudio25.04.33_inst.exe | 88MB | 13 | Cracked-software lure |
| SOLIDWORKS.Design.exe | 55MB | 21 | Cracked-software lure |
| AVKiller.exe | 60KB | 9 | **AV/EDR disabling** |
| Client.exe | 30KB | 16 | RAT client |
| Kikimoraarch.exe | 30KB | 3 | Matches Client.exe (identical size) |
| SteamSetup.exe | 571KB | 3 | Gamer lure |

**Total observed downloads: ~18,077**

### 4.3 Sample-extracted domains (algorithmic naming pattern)
AspectUtilYotta.com — BlockCore.com (active, AWS GA) — EngineFlex.com (active, same infra) — LogicIndexQuant.com — ManagerStella.com — SinkCoreYotta.com — UnitDelta.com — UnitSpanPolar.com

**Status at analysis time:** 2 resolving to identical AWS Global Accelerator IPs (76.223.54.146 / 13.248.169.48); 6 dormant. Assessed as standby infrastructure or decoys (low confidence — warrants monitoring).

---

## 4.4 Second sample: kikikmoralibrary.exe (most distributed)

| Item | Value |
|------|-------|
| SHA256 | 08d5960457d9cb6d825598adaa46586f42d08fd402bb2b75df44a9d12591971f |
| Type | PE32 .NET — same template as JavaChecker (single builder) |
| Function | **Token stealer** (Discord + browser sessions) — high density of Token-prefixed strings |
| VirusTotal | 53/70 — notable label: MSIL.Trojan-Stealer.Penetrk.A (GData); CrowdStrike 100% confidence |
| VT tags | invalid-signature (matches independent analysis), cryp (packed), detect-debug-environment (anti-analysis) |
| Extracted domains | BaseUltra.com, HelperTerra.com, TokenKinet.com, **TokenMorph.com (active: 74.208.236.232 — IONOS)**, ValueQuark.com |

**Methodology note:** the independent static findings (invalid signature, .NET, stealer) matched official VirusTotal tags before consulting them — validating the applied methodology.

---

## 4.5 Concurrent independent detection: the FakeGit campaign

On the same monitoring day (2026-07-20), the pipeline captured **5,063 SmartLoader URLs via raw.githubusercontent.com** — roughly 25% of the global URLhaus feed that day (20,119 URLs). Cross-referenced with the Trend Micro report published 2026-07-21, the indicators match the **FakeGit** campaign (7,600+ malicious repos, SmartLoader → Lumma/StealC, attributed to Water Kurita). Observed account names share the same mass-generated pattern (e.g., 115th-discomfited211, 1342342342fsdfsdfsdfsd).

**Significance:** independent same-day detection of a global campaign at the time of its public disclosure — and the Kikimora campaign may be a parallel wave of the same ecosystem (identical cracked-software lure pattern).

---

## 5. Static Analysis Results (JavaChecker.exe)

| Check | Result |
|-------|--------|
| Type | PE32 — .NET assembly (consistent with Stealc family) |
| Digital signature | **Tampered DigiCert signature** — verification failed (message digest MISMATCH) + invalid PE checksum |
| Assessment | Trust impersonation attempt: copied certificate or post-signing modification — fools superficial checks, fails real verification |
| Extracted strings | Algorithmic-style domains + token names (TokenDelta, TokenSolar, TokenChainFlow) |

---

## 6. Tactics & Techniques (MITRE ATT&CK)

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Cracked-software lures (User Execution) | T1204.002 |
| Delivery | Abuse of legitimate platform (GitHub Releases) | T1105 / T1567 |
| Defense Evasion | Tampered signature (Subvert Trust Controls) | T1553 |
| Defense Evasion | AVKiller — impair defenses | T1562.001 |
| Execution | .NET assembly | T1059 |
| C2 (possible) | Algorithmic-style domains | T1568 |

---

## 7. Gulf Context

| Indicator | Country | Status |
|-----------|---------|--------|
| QA-HOST-01-REDACTED — PureLogsStealer | Qatar | offline |
| omani-disputes.com — phishing domain | Oman | offline |
| louvree.abudhabe.info — Cobalt Strike C2 | UAE | dropped from registration (was hosted on Etisalat) |
| adminbyrequest.UAE-HOST-01.ae — Vidar | UAE | compromised |
| QatarRAT via GitHub | Qatar-named | **active** |

---

## 8. Defensive Recommendations

- **Immediate blocking:** the SHA256 hash and all eight domains
- **Policy:** block executable downloads from untrusted GitHub Releases — cracked software is the primary infection vector
- **Detection:** alert on processes terminating security services (AVKiller behavior)
- **Signature validation:** a signature's mere presence means nothing — verify its validity
- **Reporting:** reported/recommended via github.com/report-abuse (campaign still active)

---

## 9. Sources

1. URLhaus (abuse.ch) — original QatarRAT indicator, 2026-06-27
2. GitHub REST API — account, repos, and releases data, 2026-07-21
3. Static sample analysis (osslsigncode, strings) — 2026-07-21
4. ThreatFox / MalwareBazaar (abuse.ch)
5. RDAP / crt.sh / dig — domain enrichment

---

*Disclaimer: Defensive research analysis. The sample was analyzed statically in an isolated environment without execution. Indicators sourced from open threat feeds.*
