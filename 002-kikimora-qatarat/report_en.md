---
Report ID:        CTI-2026-002
Title:            Kikimora / QatarRAT Campaign
Analyst:          Mijlad Al-Subaie (@screem500)
Published:        2026-07-21
Last Updated:     2026-08-01 (v1.1 — static-analysis consistency and figure corrections)
Classification:   TLP:CLEAR
Confidence:       Moderate overall; see Key Judgments for per-judgment confidence
Status:           Published - GitHub reported
Redactions:       QA-HOST-01, UAE-HOST-01 (compromised victim domains)
---

## Key Judgments

- A distribution campaign has operated since February 2026 through a burner
  GitHub account (Kikimora-arch), accumulating 18,067 downloads as of
  2026-07-21 via cracked-software lures.
  Confidence: **High**. Basis: direct GitHub API observation of account
  creation, repository timeline, and release download counts.

- The two main binaries carry invalid Authenticode signatures — signature
  blocks likely transplanted from legitimately signed binaries (see
  Post-Publication Analysis) — and the payload set includes a likely
  AV-disabling component (AVKiller; role inferred from filename, not analyzed).
  Confidence: **High** on signature invalidity (first-party static analysis
  of both samples); **Moderate** on the transplanted-block origin.

- The "QatarRAT" label in threat feeds does not imply Qatar-exclusive
  targeting. The evidence supports a broad crimeware campaign that reached
  Gulf victims among others.
  Confidence: **Moderate to High**. Basis: lure themes are generic software
  cracks with no Gulf-specific content; feed labels commonly derive from the
  first observed victim rather than from operator intent.

- The operator is most likely Russian-speaking.
  Confidence: **Moderate**. Basis: handle drawn from East Slavic folklore,
  repository name transliterating a Russian phrase, informal English in
  descriptions. Linguistic markers can be deliberately planted (false flag),
  and no independent corroboration was obtained.

- Algorithmically-styled standby domains indicate the operator planned for
  infrastructure takedown.
  Confidence: **Moderate**. Basis: domain-naming pattern only; the standby
  domains were not observed serving content.

### Confidence Scale

High — Multiple independent sources, or direct first-party observation.
Moderate — Consistent evidence, plausible alternatives not fully excluded.
Low — Single source or circumstantial; stated as hypothesis only.

---


# Deep-Dive Investigation: Kikimora / QatarRAT Campaign - From Threat Feed to Operator Fingerprint

**Report date:** July 21, 2026
**Analyst:** Mijlad Al-Subaie - CEH · CHFI | X: @Al7lhh223 https://x.com/Al7lhh223 · GitHub: screem500 https://github.com/screem500
**Status:** Defensive analysis — cleared for publication
**Methodology:** OSINT monitoring + static malware analysis + platform intelligence (GitHub API, RDAP, CT Logs)

---

## 1. Executive Summary

This investigation began with a single URLhaus indicator ("QatarRAT") and evolved into the full exposure of a distribution campaign active since February 2026 through a burner GitHub account (Kikimora-arch), accumulating **18,067 downloads as of 2026-07-21** via cracked-software lures (FL Studio, SOLIDWORKS, Steam), with specialized components including an **AVKiller** module (role inferred from filename) and a RAT client. Static analysis revealed invalid Authenticode signatures likely transplanted from legitimately signed binaries, algorithmically-styled standby domains, and linguistic fingerprints pointing to a **Russian-speaking operator** — weakening the "Qatar-exclusive targeting" hypothesis and supporting a broad crimeware campaign that hit the Gulf among other targets.

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
| 2026-02-24 16:24 | Release v1.00.2 created (empty — files added in stages between 2026-03-11 and 2026-06-23) | GitHub API |
| 2026-06-27 | JavaChecker.exe flagged in threat feeds (QatarRAT) | URLhaus |
| 2026-07-21 | File still downloadable (online) | URLhaus |

**Note:** Account, two repos, and the (empty) release within 22 minutes = pre-staged single-purpose burner account; payloads were added later in stages (see Post-Publication Analysis).

---

## 4. Indicators of Compromise (IOCs)

### 4.1 Core infrastructure
| Indicator | Type | Details |
|-----------|------|---------|
| github.com/Kikimora-arch/solid-doodle | account/repo | Primary distribution platform — active |
| github.com/Kikimora-arch/solid-pomoemy | repo | Empty decoy |
| fe566ca92d40914438c7ce3157a6a0936ac7be94e71e6c37b95ac84177511874 | SHA256 | JavaChecker.exe |

### 4.2 Release v1.00.2 payloads (10 files — figures as of 2026-07-21)
| File | Size | Downloads | Assessed role (from filename — not analyzed) |
|------|------|-----------|----------------|
| kikikmoralibrary.exe | 1.4MB | **11,984** | Most distributed payload |
| JavaChecker.exe | 2.9MB | **4,515** | QatarRAT (this investigation's sample) |
| SolidLite.exe | 278KB | 882 | Supporting payload |
| solidbeta.exe | 33MB | 621 | Payload sized as legitimate software |
| Flstudio25.04.33_inst.exe | 88MB | 13 | Cracked-software lure |
| SOLIDWORKS.Design.exe | 55MB | 21 | Cracked-software lure |
| AVKiller.exe | 60KB | 9 | **AV/EDR disabling** |
| Client.exe | 30KB | 16 | RAT client |
| Kikimoraarch.exe | 30KB | 3 | Possibly identical to Client.exe (size match only — confirm via sha256sum on both files) |
| SteamSetup.exe | 571KB | 3 | Gamer lure |

**Total observed downloads: ~18,067 (as of 2026-07-21)**

### 4.3 Sample-extracted domains (algorithmic naming pattern)
AspectUtilYotta.com — BlockCore.com (active, AWS GA) — EngineFlex.com (active, same infra) — LogicIndexQuant.com — ManagerStella.com — SinkCoreYotta.com — UnitDelta.com — UnitSpanPolar.com

**Status at analysis time:** 2 resolving to identical AWS Global Accelerator IPs (76.223.54.146 / 13.248.169.48); 6 dormant. Assessed as standby infrastructure or decoys (low confidence — warrants monitoring).

---

## 4.4 Second sample: kikikmoralibrary.exe (most distributed)

| Item | Value |
|------|-------|
| SHA256 | 08d5960457d9cb6d825598adaa46586f42d08fd402bb2b75df44a9d12591971f |
| Type | PE32 .NET — same template as JavaChecker (single builder) |
| Function | Undetermined — high density of Token-prefixed strings (strings inference, not observed behavior; no confirmed infostealer classification) |
| VirusTotal | 53/70 — notable label: MSIL.Trojan-Stealer.Penetrk.A (GData); CrowdStrike 100% confidence |
| VT tags | invalid-signature (matches independent analysis), cryp (packed), detect-debug-environment (anti-analysis) |
| Extracted domains | BaseUltra.com, HelperTerra.com, TokenKinet.com, **TokenMorph.com (active: 74.208.236.232 — IONOS)**, ValueQuark.com |

**Methodology note:** the independent static findings (invalid signature, .NET) matched official VirusTotal tags before consulting them — validating the applied methodology.

---

## 4.5 Concurrent independent detection: the FakeGit campaign

On the same monitoring day (2026-07-20), the pipeline captured **5,063 SmartLoader URLs via raw.githubusercontent.com** — roughly 25% of the global URLhaus feed that day (20,119 URLs). Cross-referenced with the Trend Micro report published 2026-07-21, the indicators match the **FakeGit** campaign (7,600+ malicious repos, SmartLoader → Lumma/StealC, attributed to Water Kurita). Observed account names share the same mass-generated pattern (e.g., 115th-discomfited211, 1342342342fsdfsdfsdfsd).

**Significance:** independent same-day detection of a global campaign at the time of its public disclosure — and the Kikimora campaign may be a parallel wave of the same ecosystem (identical cracked-software lure pattern).

---

## 5. Static Analysis Results (JavaChecker.exe)

| Check | Result |
|-------|--------|
| Type | PE32 — .NET assembly (consistent with Stealc family) |
| Digital signature | **Invalid Authenticode signature** — verification failed (message digest MISMATCH) + invalid PE checksum; issuer identity not verified |
| Assessment | Signature block likely transplanted from a legitimately signed binary — fools superficial checks, fails real verification |
| Extracted strings | Algorithmic-style domains + token names (TokenDelta, TokenSolar, TokenChainFlow) |

![GitHub release stats](screenshots/github_stats.png)

![Invalid Authenticode signature (MISMATCH)](screenshots/fake_signature.png)
---

## 6. Tactics & Techniques (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Resource Development | Acquire Infrastructure: Web Services | T1583.006 | Burner GitHub account; payloads hosted in releases |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Cracked-software lures (FL Studio, SOLIDWORKS, Steam) |
| Execution | User Execution: Malicious File | T1204.002 | Victims run trojanized .NET installers |
| Defense Evasion | Subvert Trust Controls: Code Signing | T1553.002 | Invalid Authenticode signature (likely transplanted block) |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | AVKiller.exe component |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | RAT client beaconing |
| Command and Control | Dynamic Resolution: DGA | T1568.002 | Algorithmically-styled standby domains |
| Exfiltration | Exfiltration Over Web Service | T1567 | Data staged out via the abused platform |

---

## 7. Gulf Context (separate incidents — no established link to the Kikimora campaign)

> These incidents belong to Investigations 003 and 004 and are included for regional context only — the Qatar naming does not imply exclusive targeting (see Key Judgments).

| Indicator | Country | Status |
|-----------|---------|--------|
| QA-HOST-01 (redacted — compromised victim, reported to Qatar CERT) — PureLogsStealer | Qatar | offline |
| omani-disputes.com — phishing domain | Oman | offline |
| louvree.abudhabe.info — Cobalt Strike C2 | UAE | dropped from registration (was hosted on Etisalat) |
| UAE-HOST-01 — Vidar | UAE | compromised |
| QatarRAT via GitHub | Qatar-named | **active** |

---

## 8. Defensive Recommendations

- **Immediate blocking:** both sample SHA256 hashes. **Monitor only, do not block:** the 13 extracted domains (low confidence — 6 dormant with generic business names that may belong to legitimate parties)
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





## Post-Publication Analysis (added 2026-07-31)

### Payload family divergence
The two main payloads belong to different families with distinct behaviors. kikikmoralibrary.exe (1.34 MB) is labeled trojan.msil/cryp — a generic crypter. JavaChecker.exe (2.77 MB) is labeled trojan.msil/disco, with threat categories including ransomware and behavior tags spreader and checks-usb-bus — indicating USB-based self-propagation that operates beyond the GitHub download counter. Neither sample is classified as an infostealer; impact claims are therefore limited to documented behavior.

### Note on multi-name distribution
VirusTotal records kikikmoralibrary.exe (SHA256: 08d59604...) under unrelated names — ContextContextDelta.exe, RC_ConnectedAccount.exe, CvMega.exe, mppr.exe, ekoo9.exe — and JavaChecker.exe under the name AspectSigma.exe, indicating circulation beyond this repository. This reflects subsequent spread across other channels after initial deployment (see upload timeline below).

### Upload timeline vs. VirusTotal first sightings
Repository asset timestamps show both main payloads were uploaded to GitHub before their first documented appearance: kikikmoralibrary.exe uploaded 2026-04-06 18:29 UTC, first submitted to VirusTotal 2026-04-07 07:35 UTC (13 hours later); JavaChecker.exe uploaded 2026-06-23 11:25 UTC, first submitted 2026-06-24 12:02 UTC (under 25 hours later). The ordering holds under both VirusTotal fields (First Submission and First Seen In The Wild), making the repository the earliest documented distribution point for both binaries. Asset timestamps also reveal staged deployment: an initial payload (SOLIDWORKS.Design.exe, 2026-03-11), a second (SolidLite.exe, 2026-03-31), a bulk batch of six files on 2026-04-06/07 — two of them, AVKiller.exe and SteamSetup.exe, uploaded one second apart, indicating scripted upload — and later additions on 2026-05-29 and 2026-06-23. VT first-submission dates record first sighting by VirusTotal and do not establish first existence.

### Staging-repository pattern (primary finding)
Download distribution is inconsistent with human, lure-driven downloads. The two main payloads hold ~92% of all downloads (18,665 of 20,233 as of 2026-07-31), led by kikikmoralibrary.exe with 12,886 (64%) — a filename with no lure value — while Client.exe, uploaded 34 minutes later on the same day, has only 16 downloads (~800x difference), solidbeta.exe, uploaded 6 hours earlier, has 621, and SolidLite.exe, uploaded six days before kikikmoralibrary and thus with a longer exposure window, has 882. Identical or longer exposure windows with an ~800x spread concentrated on the least convincing lure indicate retrieval driven by direct-URL fetching rather than lure attractiveness — consistent with either (a) the repository functioning as a staging point where a loader or second-stage component pulls payloads programmatically, or (b) direct links to these assets circulating on a high-traffic channel; current data cannot distinguish between the two. This pattern also explains why eight of ten files recorded zero growth during the 2026-07-25 → 07-31 observation window. Confidence: medium — the download counter cannot separate automated pulls from human downloads.

### Binary independence and discarded indicators
SSDEEP and TLSH fuzzy hashes differ completely between the two payloads, confirming independent binaries rather than successive versions — consistent with their distinct family labels (msil/cryp vs msil/disco). Their signature blocks also originate from different sources: kikikmoralibrary.exe's signature is dated 2017-11-01 (8+ years before deployment), JavaChecker.exe's is dated 2025-05-12 (13 months before deployment). Three apparent indicators were examined and dismissed: (1) the identical imphash (f34d5f2d...) carries no linkage value — both are .NET assemblies importing only mscoree.dll!_CorExeMain, an imphash shared by millions of .

NET binaries; (2) the future-dated PE timestamps (2062/2063) reflect Roslyn deterministic builds replacing TimeDateStamp with a hash-derived value — not timestomping; (3) the absence of fresh VT submissions since 2026-05-06 / 2026-06-27 despite continued download growth proves nothing either way — most downloaders never submit samples, an already-detected hash (55/70 and 53/69 respectively) has little reason for re-upload, and automated pipelines filter known hashes; it cannot distinguish automated from human retrieval.

### Signature block origin (kikikmoralibrary.exe only)
The sample carries a signature dated 2017-11-01 — more than eight years before its 2026 deployment — with an invalid Authenticode digest (MISMATCH), indicating the block was likely transplanted from an older, legitimately signed binary. This does not generalize to JavaChecker.exe, whose signature (2025-05-12) comes from a different, much newer source.

### Azure Blob Storage pivot
A VirusTotal submission name for kikikmoralibrary.exe embeds an Azure SAS token (sktid: 398a6654-997b-47e9-b12b-9515b896b4de; skoid: 96c2d410-5711-43a1-aedd-ab1947aa7ab0) with a one-hour validity window on 2026-05-05 (13:07–14:07 UTC). This records that the file was fetched at least once via an Azure Blob URL — the query string survived as the submission filename, most likely from a downstream fetcher (possibly an analyst or automated sandbox, not necessarily the operator). The tenant and object IDs are retained as pivots for follow-up; they identify the issuing Azure AD tenant, which may belong to a compromised legitimate party or an intermediary rather than the operator. The token expired 2026-05-05 and is safe to publish.
