---
Report ID:        CTI-2026-003
Title:            Live ClearFake Loader on a Compromised UAE Website (Redacted)
Analyst:          Mijlad Al-Subaie (@screem500)
Published:        2026-07-24
Last Updated:     2026-07-26
Classification:   TLP:CLEAR
Confidence:       High overall; see Key Judgments for per-judgment confidence
Status:           Reported to aeCERT - awaiting remediation
Redactions:       UAE-HOST-01 (victim identity withheld per Responsible Disclosure Policy)
---

# Investigation 003: Active ClearFake Loader on a Compromised UAE Website

> **Disclosure Note:** The victim identity (UAE-HOST-01) is withheld per the
> [Responsible Disclosure Policy](../RESPONSIBLE_DISCLOSURE.md) — released upon
> confirmed remediation or 90 days from notification (2026-07-25), whichever
> comes first. Full raw evidence is kept off public release, available to
> official bodies on request.

Arabic version: [report_ar.md](report_ar.md)

---

## 1. Executive Summary

During routine monitoring of a ThreatFox indicator (UAE-HOST-01 — tagged as
compromised and distributing Vidar via ClickFix), the page appeared
superficially clean. Deeper inspection revealed a malicious JavaScript loader
injected at the page tail — an active ClearFake-family loader, live at analysis
time. Full raw evidence was reported to aeCERT on 2026-07-25.

---

## 2. Key Judgments

- The compromise was live and active at analysis time, with a beacon
  collecting visitor data in real time.
  Confidence: **High**. Basis: direct first-party observation of the injected
  code and its live behavior.

- The loader applies conditional cloaking that hides the lure from security
  scanners.
  Confidence: **High**. Basis: the conditional display logic is present in the
  injected code itself.

- The owning organization was most likely unaware of the compromise.
  Confidence: **Moderate**. Basis: the legitimate service continued operating
  alongside the injected code; no direct contact with the owner was made
  before notification.

- The injected code is under active development rather than a legacy remnant.
  Confidence: **Moderate**. Basis: developer comments referencing untested
  behavior remain in the deployed script; no version history was obtainable.

### Confidence Scale

High — Multiple independent sources, or direct first-party observation.
Moderate — Consistent evidence, plausible alternatives not fully excluded.
Low — Single source or circumstantial; stated as hypothesis only.

---

## 3. Injected Code Analysis

| Element | Function | Significance |
|---------|----------|--------------|
| `_cf_verified` cookie | "Verified" marker on the victim device | ClearFake (cf) signature — the lure is shown only once |
| `_wp_perf_ok` cookie | Secondary disguised cookie | Impersonates a legitimate WordPress performance plugin |
| Heartbeat beacon | Sends domain + userAgent + path to `/beacon/` | Live visitor surveillance — data reaches the operator instantly |
| `show_` + platform | Conditional per-OS display | Selective targeting (Windows/macOS) — explains the clean appearance to scanners |
| Developer comments | `// server never saw Obf JS heartbeats` | Actively developed code — live infrastructure, not legacy remnants |

![Injected ClearFake loader](screenshots/injected_code.png)

![Injected code part 2](screenshots/injected_code1.png)

---

## 4. Why Did the Page Look Clean?

The loader applies conditional cloaking: it inspects the visitor's User-Agent
and behavior, serving the lure (a fake browser update) only to matching
victims, while security scanners and crawlers see a legitimate landing page for
the real "Admin By Request" product.

That choice is deliberate. The product's name makes the "paste this command as
administrator" step (ClickFix) appear logical to the victim.

---

## 5. Timeline (UTC)

| Date | Event |
|------|-------|
| 2026-07-24 | Indicator surfaced in ThreatFox; live code analysed; raw evidence preserved |
| 2026-07-25 | Reported to aeCERT with full evidence |
| 2026-07-26 | Published in redacted form per the Responsible Disclosure Policy |

---

## 6. Tactics & Techniques (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Reconnaissance | Gather Victim Host Information | T1592 | Beacon collects userAgent, platform and path per visitor |
| Resource Development | Compromise Infrastructure: Domains | T1584.001 | Legitimate UAE site abused as the delivery platform |
| Initial Access | Drive-by Compromise | T1189 | Loader injected into a legitimate web page |
| Execution | User Execution: Malicious File | T1204.002 | Fake update lure (ClickFix) pushes the victim to run a command |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | ClickFix instructs the victim to paste a command as administrator |
| Defense Evasion | Obfuscated Files or Information | T1027 | Obfuscated script plus conditional cloaking |
| Defense Evasion | Impersonation | T1656 | Fake browser-update prompt |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Heartbeat beacon over HTTP(S) |
| Exfiltration | Exfiltration Over Web Service | T1567 | Visitor data sent to the `/beacon/` path |

---

## 7. Conclusion and Action

- The compromise was live and active at analysis time (2026-07-24), still
  harvesting visitor data.
- The owning organization (UAE-HOST-01) was likely unaware — notified via
  aeCERT on 2026-07-25.
- Monitoring of the site's status continues; identity release is pending
  confirmation of remediation.

---

## 8. Indicators of Compromise

> The victim-identifying full indicator is withheld per policy — shared with
> official bodies only.

Machine-readable indicators:
[`iocs_003_uae_clearfake_stix.json`](iocs_003_uae_clearfake_stix.json) (STIX 2.1)

These indicators are behavioural patterns rather than fixed values, which is
why no plain-text IOC list accompanies this report.

| Indicator | Type | Note |
|-----------|------|------|
| UAE-HOST-01 | host | Compromised — live ClearFake loader, cloaked. REDACTED |
| `/beacon/` endpoint | url pattern | Heartbeat exfiltration path |
| `_cf_verified` | cookie | ClearFake verification marker |
| `_wp_perf_ok` | cookie | Disguised secondary marker |

---

## 9. Notification and Reporting

| Recipient | Date | Status |
|-----------|------|--------|
| aeCERT (UAE) | 2026-07-25 | Submitted — awaiting remediation |

---

*Defensive research analysis. Indicators are drawn from open threat feeds and
first-party analysis. Samples are never executed. TLP:CLEAR*
