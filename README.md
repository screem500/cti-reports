# CTI Reports - استخبارات التهديدات السيبرانية

Independent cyber threat intelligence research with a focus on the Gulf and Middle East - built on a self-hosted daily monitoring pipeline (URLhaus, ThreatFox, MalwareBazaar, CISA KEV) and hands-on investigations.

بحوث مستقلة في استخبارات التهديدات السيبرانية بتركيز على الخليج والشرق الأوسط - مبنية على منظومة رصد يومية ذاتية وتحقيقات ميدانية.

---

## 📁 التقارير | Reports

### 🔵 Investigation 004: Gulf-Themed Lures on Foreign Infrastructure (July 2026)
Five campaigns abusing Gulf-themed naming (qatar/omani/gulf) as lures: PureLogsStealer, reverse-base64 loader, ClearFake-macOS, Potemkin, and live SmartLoader-MaaS on GitHub. All live indicators reported - GitHub T&S receipt confirmed.

- [Arabic report | التقرير العربي](004-gulf-themed-lures/report_ar.md)
- [English report | التقرير الإنجليزي](004-gulf-themed-lures/report_en.md)
- [IOCs (TXT)](004-gulf-themed-lures/iocs_gulf_lures.txt) · [IOCs (STIX 2.1)](004-gulf-themed-lures/iocs_gulf_lures_stix.json)

### 🟣 Investigation 003: Live ClearFake Loader on Compromised UAE Website (July 2026)
Active ClearFake loader discovered in-the-wild on a compromised UAE site, using conditional cloaking and live visitor beacons - raw evidence preserved. Reported to aeCERT on 2026-07-25.

- [Evidence report | تقرير الدليل](003-uae-clearfake-live/live_evidence_UAE-HOST-01.md)

### 🔴 Investigation 002: Kikimora / QatarRAT Campaign (July 2026)
Deep-dive from a single feed indicator to a full distribution campaign: ~18,000 downloads, tampered DigiCert signature, AVKiller component, Russian-speaking operator fingerprints.

- [Arabic report | التقرير العربي](002-kikimora-qatarat/report_ar.md)
- [English report | التقرير الإنجليزي](002-kikimora-qatarat/report_en.md)

### 🟠 Investigation 001: ClearFake on Compromised Iranian Infrastructure (July 2026)
35 compromised Iranian (.ir) civilian domains serving 58 malicious URLs amid the Iran–US conflict - plus a Cobalt Strike C2 and a compromised UAE site distributing Vidar.

- [Arabic report | التقرير العربي](001-clearfake-iran/report_ar.md)
- [English report | التقرير الإنجليزي](001-clearfake-iran/report_en.md)

---

## 🛠️ المنهجية | Methodology

- Daily automated IOC collection and Gulf-focused filtering
- Static malware analysis in isolated environments (no execution)
- Platform intelligence: GitHub API, RDAP, CT logs, passive DNS
- Attribution with explicit confidence levels - evidence over assumptions
- IOCs published in both human-readable (TXT) and machine-readable (STIX 2.1) formats

---

👤 عن المحلل | About the Analyst
Mijlad Al-Subaie (مجلاد السبيعي) - Cybersecurity Expert · CEH · CHFI · AI Agent Security Researcher - Saudi Arabia
•  X (Twitter): @Al7lhh223 https://x.com/Al7lhh223
•  GitHub: @screem500 https://github.com/screem500

## ⚠️ Disclaimer

All research is defensive in nature. Indicators are sourced from open threat feeds and first-party analysis. Samples are never executed.

*جميع البحوث ذات طابع دفاعي. المؤشرات من feeds مفتوحة المصدر وتحليلات مباشرة.*

----

🔖 Keywords
threat intelligence CTI OSINT malware analysis IOC STIX QatarRAT Kikimora ClearFake FakeGit SmartLoader StealC Cobalt Strike Vidar Gulf cyber threats Saudi Arabia cybersecurity استخبارات التهديدات الأمن السيبراني تحليل برمجيات خبيثة مؤشرات الاختراق
