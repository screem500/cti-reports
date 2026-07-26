---
Report ID:        CTI-2026-003
Title:            Live ClearFake Loader on a Compromised UAE Website (Redacted)
Analyst:          Mijlad Al-Subaie (@screem500)
Published:        2026-07-24
Last Updated:     2026-07-26
Classification:   TLP:CLEAR
Confidence:       High
Status:           Reported to aeCERT - awaiting remediation
Redactions:       UAE-HOST-01 (victim identity withheld per Responsible Disclosure Policy)
---

# تحقيق 003: لودر ClearFake نشط على موقع إماراتي مخترق
# Investigation 003: Active ClearFake Loader on a Compromised UAE Website

> ⚠️ **ملاحظة الإفصاح | Disclosure Note:** هوية الجهة المخترقة (UAE-HOST-01) محجوبة وفق [سياسة الإفصاح المسؤول](../RESPONSIBLE_DISCLOSURE.md) — تُكشف بعد تأكيد المعالجة أو بعد 90 يوماً من الإبلاغ (2026-07-25)، أيهما أسبق. الدليل الخام الكامل محفوظ خارج النشر العام ومتاح للجهات الرسمية عند الطلب.
> The victim identity (UAE-HOST-01) is withheld per the Responsible Disclosure Policy — released upon confirmed remediation or 90 days from notification (2026-07-25), whichever comes first. Full raw evidence is kept off public release, available to official bodies on request.

---

## 🇸🇦 القسم العربي

### 1. الملخص التنفيذي

أثناء متابعة دورية لمؤشر مرصود في ThreatFox (`adminbyrequest.UAE-HOST-01` — موسوم كمخترق يوزع Vidar عبر ClickFix)، تبيّن أن الصفحة تعرض محتوى نظيفاً ظاهرياً. الفحص الأعمق كشف **كود JavaScript خبيثاً مزروعاً في ذيل الصفحة** — لودر نشط من عائلة ClearFake يعمل لحظة التحليل. تم الإبلاغ لـ aeCERT بالدليل الخام الكامل بتاريخ 2026-07-25.

### 2. الأحكام الرئيسية | Key Judgments

- **الحكم 1:** الاختراق نشط وحي وقت التحليل، مع بنية beacon تجمع بيانات الزوار لحظياً. الثقة: **عالية**. الأساس: ملاحظة مباشرة للكود المزروع والسلوك الحي.
- **الحكم 2:** اللودر يطبّق تمويهاً شرطياً (Cloaking) يخفي الفخ عن الفاحصين الأمنيين. الثقة: **عالية**. الأساس: منطق العرض المشروط داخل الكود نفسه.
- **الحكم 3:** الجهة المالكة غير مدركة للاختراق على الأرجح. الثقة: **متوسطة**. الأساس: استمرار الخدمة الشرعية بالتوازي مع الكود المزروع.

### 3. تحليل الكود المزروع

| العنصر | الوظيفة | الدلالة |
|--------|---------|---------|
| كوكي `_cf_verified` | علامة "تم التحقق" في جهاز الضحية | توقيع ClearFake (cf) — لا يُعرض الفخ مرتين |
| كوكي `_wp_perf_ok` | كوكي ثانٍ متخفٍّ | انتحال مظهر إضافة أداء WordPress شرعية |
| Heartbeat beacon | يرسل domain + userAgent + المسار لخادم `/beacon/` | تجسس حي على كل زائر — بياناته تصل للمشغل فورياً |
| `show_`+platform | عرض مشروط حسب نظام الضحية | استهداف انتقائي (Windows/macOS) — يفسر المظهر النظيف للفاحصين (Cloaking) |
| تعليقات المطوّر في الكود | `// server never saw Obf JS heartbeats` | الكود قيد تطوير نشط — بنية حية وليست بقايا قديمة |

![Injected ClearFake loader](screenshots/injected_code.png)

![Injected code part 2](screenshots/injected_code1.png)

### 4. لماذا بدت الصفحة نظيفة؟

اللودر يطبّق **تمويهاً شرطياً (Cloaking)**: يفحص User-Agent وسلوك الزائر، ويقدّم الفخ (تحديث متصفح مزيف) للضحايا المطابقين فقط، بينما يرى الفاحص الأمني والزاحف صفحة تسويقية سليمة لمنتج "Admin By Request" الحقيقي — وهو اختيار متعمد: اسم المنتج يجعل طلب "الصق الأمر كمسؤول" يبدو منطقياً للضحية (تقنية ClickFix).

### 5. الخط الزمني | Timeline (UTC)

| التاريخ | الحدث |
|---------|-------|
| 2026-07-24 | رصد المؤشر في ThreatFox + تحليل الكود الحي + حفظ الدليل الخام |
| 2026-07-25 | الإبلاغ لـ aeCERT بالدليل الكامل |
| 2026-07-26 | النشر بصيغة محجوبة وفق سياسة الإفصاح المسؤول |

### 6. MITRE ATT&CK Mapping

| التكتيك | التقنية | المعرف | الملاحظة |
|---------|---------|--------|----------|
| Initial Access | Drive-by Compromise | T1189 | لودر مزروع بصفحة ويب شرعية مخترقة |
| Execution | User Execution: Malicious File | T1204.002 | فخ تحديث مزيف (ClickFix) يدفع الضحية للصق أمر |
| Defense Evasion | Obfuscated Files or Information | T1027 | كود مشوش + تمويه شرطي Cloaking |
| Collection | Input Capture | T1056 | beacon يجمع بيانات الزوار لحظياً |
| Exfiltration | Exfiltration Over Web Service | T1567 | إرسال البيانات لمسار /beacon/ |

---

## 🇬🇧 English Section

### 1. Executive Summary

During routine monitoring of a ThreatFox indicator (`adminbyrequest.UAE-HOST-01` — tagged compromised, distributing Vidar via ClickFix), the page appeared superficially clean. Deeper inspection revealed a **malicious JavaScript loader injected at the page tail** — an active ClearFake-family loader, live at analysis time. Full raw evidence was reported to aeCERT on 2026-07-25.

### 2. Injected Code Analysis

| Element | Function | Significance |
|---------|----------|--------------|
| `_cf_verified` cookie | "Verified" marker on victim device | ClearFake (cf) signature — lure shown once |
| `_wp_perf_ok` cookie | Secondary disguised cookie | Impersonates a legitimate WordPress performance plugin |
| Heartbeat beacon | Sends domain + userAgent + path to `/beacon/` | Live visitor surveillance — data reaches the operator instantly |
| `show_`+platform | Conditional per-OS display | Selective targeting (Windows/macOS) — explains the clean appearance to scanners (Cloaking) |
| Developer comments in code | `// server never saw Obf JS heartbeats` | Actively developed code — live infrastructure, not legacy remnants |

### 3. Why Did the Page Look Clean?

The loader applies **conditional cloaking**: it inspects the visitor's User-Agent and behavior, serving the lure (fake browser update) only to matching victims, while security scanners see a legitimate landing page for the real "Admin By Request" product — a deliberate choice: the product's name makes the "paste this command as admin" step (ClickFix) appear logical to the victim.

### 4. Conclusion & Action

- The compromise was **live and active** at analysis time (2026-07-24) — still harvesting visitor data
- The owning organization (UAE-HOST-01) was likely unaware — notified via aeCERT on 2026-07-25
- Ongoing monitoring of the site's status; identity release pending remediation confirmation

---

## المؤشرات | IOCs

> المؤشر الكامل المعرّف للضحية محجوب وفق السياسة — يُشارك مع الجهات الرسمية فقط.
> The victim-identifying full indicator is withheld per policy — shared with official bodies only.

```
adminbyrequest.UAE-HOST-01      (compromised — live ClearFake loader, cloaked) [REDACTED]
/beacon/ endpoint               (heartbeat exfiltration path)
cookies: _cf_verified, _wp_perf_ok
```

## الإبلاغ | Notification and Reporting

| الجهة | التاريخ | الحالة |
|-------|---------|--------|
| aeCERT (الإمارات) | 2026-07-25 | تم الإرسال — بانتظار المعالجة |

*تحليل دفاعي بحثي — For defensive research purposes. TLP:CLEAR*
