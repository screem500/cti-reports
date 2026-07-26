---
Report ID:        CTI-2026-004
Title:            Gulf-Themed Lures on Foreign Infrastructure
Analyst:          Mijlad Al-Subaie (@screem500)
Published:        2026-07-25
Last Updated:     2026-07-26
Classification:   TLP:CLEAR
Confidence:       Moderate
Status:           Reported - GitHub T&S receipt confirmed; national CERTs notified
Redactions:       QA-HOST-01 (compromised victim domain)
---

# تحقيق 004: طعوم بأسماء خليجية — ظاهرة Gulf-Themed Lures في بنى تحتية أجنبية

**تاريخ التقرير:** 25 يوليو 2026
**المحلل:** Mijlad Al-Subaie (مجلاد السبيعي) — CEH · CHFI | X: @Al7lhh223 https://x.com/Al7lhh223 · GitHub: screem500 https://github.com/screem500
**الحالة:** تحليل دفاعي — للنشر
**الإبلاغ:** بتاريخ 2026-07-25 تم: إبلاغ GitHub Trust & Safety عن مستودعي SmartLoader-MaaS النشطين (تأكيد استلام وارد)، وإشعار الجهات المعنية في سلطنة عُمان ودولة قطر بالمؤشرين المرتبطين بطعومهما (omani-disputes.com / QA-HOST-01 [محجوب - REDACTED])
**المنهجية:** رصد مفتوح المصدر (URLhaus, ThreatFox) + استخبارات منصات (WHOIS/RDAP, GitHub API) — بدون تشغيل أي عينة
**يرتبط بـ:** التحقيق 001 (ClearFake-iran) · التحقيق 002 (Kikimora/QatarRAT) · التحقيق 003 (UAE ClearFake Live)
**الحجب:** النطاق QA-HOST-01 ضحية مخترقة محتملة — هويته محجوبة وفق سياسة الإفصاح المسؤول، وبُلّغ بها المركز الوطني القطري والمسجّل (PDR) بتاريخ 2026-07-25

---

## 1. الملخص التنفيذي

رصدت منظومة المتابعة اليومية خمس حملات مستقلة تستخدم **أسماء خليجية صريحة** (qatar, omani, gulf) كطعوم في نطاقات ومسارات توزيع، بينما تقع بنيتها التحتية الفعلية كلها خارج المنطقة (ألمانيا، الولايات المتحدة). التحليل يفرّق بين نمطين:

- **نطاقات شرعية مخترقة** ذات تسمية خليجية (`QA-HOST-01 [محجوب - REDACTED]` — مسجل منذ 2023)
- **نطاقات مسجلة خصيصاً للحملة** (`omani-disputes.com` — سُجل قبل 5 أسابيع من استخدامه)

الخلاصة التحليلية: التسمية الخليجية **ليس دليلاً كافياً على استهداف حصري للخليج** (كما أثبت التحقيق 002 في حالة QatarRAT)، لكنها في حالتين على الأقل تُظهر اختياراً متعمداً لهوية إقليمية كطُعم — وهو ما يستدعي الرصد المستمر والإبلاغ المنسق.

---

## 2. المؤشرات الخمسة

| # | المؤشر | البرمجية | التسمية الخليجية | الحالة وقت الرصد |
|---|--------|----------|------------------|-------------------|
| 1 | `QA-HOST-01 [محجوب - REDACTED]/sonic.exe` + `/fallacy001.exe` | PureLogsStealer | قطر | offline |
| 2 | `omani-disputes.com/txt/adkbjdd.txt` | reverse base64 loader | عُمان | offline |
| 3 | `jnhygwu4.gulfbreezervrentals.com` | ClearFake (macOS) | الخليج عامة | offline |
| 4 | `shaggulf-sold.xyz/avast_update` | Potemkin Loader | الخليج عامة | offline |
| 5 | حسابا GitHub (`rsaudio`, `Alpacareticulitermeslucifugus340`) | SmartLoader-MaaS | — | **online** |

---

## 3. تحليل البنية التحتية

### 3.1 QA-HOST-01 [محجوب - REDACTED] — نطاق شرعي مخترق (ثقة متوسطة)

| البند | القيمة |
|-------|--------|
| تاريخ التسجيل | 2023-09-19 (قبل الحملة بسنتين ونصف) |
| Registrar | PDR Ltd. (PublicDomainRegistry) |
| الاستضافة | 5.9.143.30 — Hetzner، Falkenstein، ألمانيا |
| DNSSEC | غير موقّع |

**الاستدلال:** نطاق عمره يتجاوز الحملة بكثير + استضافة ألمانية رخيصة + توزيع Stealer من مسارين بأسماء عشوائية (`sonic.exe`, `fallacy001.exe`) = نمط موقع مخترق استُغل كمنصة توزيع، لا نطاقاً مسجلاً للهجوم.

### 3.2 omani-disputes.com — مسجل خصيصاً للحملة (ثقة عالية)

| البند | القيمة |
|-------|--------|
| تاريخ التسجيل | **2026-05-29** |
| أول استخدام مرصود | 2026-07-05 (بعد 5 أسابيع) |
| Registrar | NiceNIC International |
| الاستضافة | 3.144.33.123 — Amazon Technologies (AWS)، الولايات المتحدة |

**الاستدلال:** الاسم ("نزاعات عُمانية") يوحي بصفحة خلافات/مطالبات — قالب تصيد كلاسيكي. التسجيل الحديث + الاستخدام السريع + المسار النصي الخام (`/txt/adkbjdd.txt` محمّل base64 معكوس) = بنية أُعدت لهذه الحملة تحديداً.

### 3.3 gulfbreezervrentals.com — حلقة وصل مع التحقيق 003

المؤشر موسوم في URLhaus بـ `ClearFake,mac-0x68dc,macOS` — تأكيد إضافي على ما وثقه التحقيق 003 ميدانياً: **ClearFake لم تعد حملة Windows فقط**، بل توسعت لاستهداف macOS بطعوم تحديث مزيفة. النطاق مسجل بنمط "تأجير مركبات خليجية" — تمويه تجاري إقليمي.

### 3.4 SmartLoader-MaaS عبر GitHub — نشط وقت النشر

مستودعان يوزعان أرشيفات ZIP خبيثة عبر `raw.githubusercontent.com`:

- `rsaudio/second-brain` — متنكر كمشروع "second_brain_v3.7"
- `Alpacareticulitermeslucifugus340/rockyou_uzb` — متنكر كقائمة كلمات مرور أوزبكية (نفس أسلوب تمويه Kikimora-arch في التحقيق 002)

**النمط المشترك:** استغلال سمعة GitHub كبنية توزيع + تمويه بمشاريع تقنية مفتوحة المصدر المظهر.

---

## 4. الخط الزمني الموحد

| التاريخ | الحدث |
|---------|-------|
| 2026-05-29 | تسجيل omani-disputes.com (NiceNIC) |
| 2026-06-22 | رفع حمولتي SmartLoader-MaaS على GitHub |
| 2026-07-05 | omani-disputes.com يوزع loader (أول رصد) |
| 2026-07-14 | QA-HOST-01 [محجوب - REDACTED] يوزع PureLogsStealer (مساران خلال 7 دقائق) |
| 2026-07-20 | gulfbreezervrentals.com يوزع ClearFake-macOS |
| 2026-07-23 | shaggulf-sold.xyz يوزع Potemkin |
| 2026-07-25 | مؤشرا SmartLoader-MaaS ما زالا online |

---

## 5. الحكم التحليلي

1. **ليست حملة واحدة** — العائلات مختلفة (Stealer, Loader, ClearFake, MaaS) والبنية موزعة. الصحيح وصفها بـ "ظاهرة" لا "حملة".
2. **التسمية الخليجية طُعم لا دليل استهداف** — يتسق مع التصحيح التحليلي في التحقيق 002. لكن تكرارها (5 حالات في 6 أسابيع) يستحق الرصد كمؤشر إنذار مبكر.
3. **أولوية الإجراء:** مؤشرا SmartLoader-MaaS النشطان — يستوجبان إبلاغ GitHub Trust & Safety فوراً.

## 6. التوصيات

| الإجراء | الجهة | الأولوية |
|---------|-------|----------|
| إبلاغ عن مستودعي SmartLoader-MaaS | GitHub Trust & Safety | 🔴 عاجلة |
| إبلاغ عن omani-disputes.com | المركز الوطني للأمن السيبراني العُماني (mCERT) + NiceNIC abuse | 🟠 عالية |
| إبلاغ عن QA-HOST-01 [محجوب - REDACTED] | المركز الوطني القطري للأمن السيبراني + PDR abuse | 🟠 عالية |
| إضافة المؤشرات لقواعد الرصد المحلية | فرق SOC الخليجية | 🟡 متابعة |

---

## 7. ملاحق IOCs

انظر ملف `iocs_gulf_lures.txt` المرفق — يشمل النطاقات، الروابط الكاملة، العناوين IP، ومراجع URLhaus لكل مؤشر.

---

## ⚠️ إخلاء مسؤولية

تحليل دفاعي بحت. جميع المؤشرات من فيدات تهديدات مفتوحة المصدر (URLhaus, ThreatFox) وبيانات تسجيل عامة. لم يتم تشغيل أو تحميل أي عينة خبيثة. مستويات الثقة مصرح بها صراحة لكل استنتاج.
