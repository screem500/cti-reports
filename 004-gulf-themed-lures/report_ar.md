---
Report ID:        CTI-2026-004
Title:            Gulf-Themed Lures on Foreign Infrastructure
Analyst:          Mijlad Al-Subaie (@screem500)
Published:        2026-07-25
Last Updated:     2026-08-01 (v1.1 — تصحيحات تحليلية وإصلاح حجب)
Classification:   TLP:CLEAR
Confidence:       Moderate overall; see Key Judgments for per-judgment confidence
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

رصدت منظومة المتابعة اليومية **خمسة مؤشرات مستقلة** خلال ستة أسابيع، منها **اثنان فقط يحملان تسمية خليجية صريحة** (قطر، عُمان)، وثالث بتطابق لفظي منخفض الثقة (shaggulf-sold.xyz)، بينما أظهر التحليل أن الرابع (gulfbreezervrentals.com) اسم شركة أمريكية من مدينة Gulf Breeze في فلوريدا ولا صلة له بالخليج. تقع البنية التحتية الفعلية كلها خارج المنطقة (ألمانيا، الولايات المتحدة). التحليل يفرّق بين نمطين:

- **نطاقات شرعية مخترقة** ذات تسمية خليجية (`QA-HOST-01 [محجوب - REDACTED]` — مسجل منذ 2023)
- **نطاقات مسجلة خصيصاً للحملة** (`omani-disputes.com` — سُجل قبل 5 أسابيع من استخدامه)

الخلاصة التحليلية: التسمية الخليجية **ليس دليلاً كافياً على استهداف حصري للخليج** (كما أثبت التحقيق 002 في حالة QatarRAT)، لكنها في الحالتين المؤكدتين (قطر، عُمان) تُظهر اختياراً متعمداً لهوية إقليمية كطُعم — وهو ما يستدعي الرصد المستمر والإبلاغ المنسق.

---

## 2. المؤشرات الخمسة

| # | المؤشر | البرمجية | التسمية الخليجية | الحالة وقت الرصد |
|---|--------|----------|------------------|-------------------|
| 1 | `QA-HOST-01 [محجوب - REDACTED]/sonic.exe` + `/fallacy001.exe` | PureLogsStealer | قطر | offline |
| 2 | `omani-disputes.com/txt/adkbjdd.txt` | reverse base64 loader | عُمان | offline |
| 3 | `jnhygwu4.gulfbreezervrentals.com` | ClearFake (macOS) | لا ينطبق — اسم شركة من Gulf Breeze فلوريدا (موقع أمريكي مخترق على الأرجح) | offline |
| 4 | `shaggulf-sold.xyz/avast_update` | Potemkin Loader | الخليج عامة؟ (ثقة منخفضة — تطابق لفظي لا دليل تسمية مقصودة) | offline |
| 5 | حسابا GitHub (`rsaudio`, `Alpacareticulitermeslucifugus340`) | SmartLoader-MaaS | — | **online** |

---

## 3. تحليل البنية التحتية

### 3.1 QA-HOST-01 [محجوب - REDACTED] — نطاق شرعي مخترق (ثقة متوسطة)

| البند | القيمة |
|-------|--------|
| تاريخ التسجيل | 2023 (قبل الحملة بنحو سنتين ونصف) |
| Registrar | PDR Ltd. (PublicDomainRegistry) |
| الاستضافة | Hetzner، ألمانيا (عنوان IP محجوب — كان نشره يبطل حجب النطاق) |
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

المؤشر موسوم في URLhaus بـ `ClearFake,mac-0x68dc,macOS` — تأكيد إضافي على ما وثقه التحقيق 003 ميدانياً: **ClearFake لم تعد حملة Windows فقط**، بل توسعت لاستهداف macOS بطعوم تحديث مزيفة.

**تصحيح (2026-08-01):** اسم النطاق لا يشير إلى الخليج العربي. قراءته الصحيحة «Gulf Breeze RV Rentals» — وGulf Breeze مدينة في فلوريدا على خليج المكسيك، وRV rentals تأجير بيوت متنقلة. الأرجح أنه موقع شركة أمريكية صغيرة **مخترق**، ويدعم ذلك النطاق الفرعي العشوائي (`jnhygwu4`) المطابق لنمط ClearFake المعروف في استغلال مواقع شرعية مخترقة. لذلك استُبعد من عدّ «التسمية الخليجية»، وبقي احتسابه دليلاً على توسع ClearFake نحو macOS فقط.

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

## 5. التكتيكات والتقنيات (MITRE ATT&CK)

التقنيات المرصودة عبر المؤشرات الخمسة. لا تنطبق كل تقنية على كل حالة؛ عمود
الدليل يحدد الحالة المعنية.

| التكتيك | التقنية | المعرف | الدليل |
|---------|---------|--------|--------|
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | omani-disputes.com مسجّل قبل 5 أسابيع من أول استخدام مرصود |
| Resource Development | Compromise Infrastructure: Domains | T1584.001 | QA-HOST-01 — نطاق شرعي مسجّل 2023 ثم أُسيء استخدامه |
| Resource Development | Acquire Infrastructure: Web Services | T1583.006 | حسابا GitHub مؤقتان يستضيفان SmartLoader-MaaS |
| Initial Access | Drive-by Compromise | T1189 | ClearFake (macOS) على jnhygwu4.gulfbreezervrentals.com |
| Execution | User Execution: Malicious File | T1204.002 | تشغيل الضحية لـ sonic.exe / fallacy001.exe / avast_update |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Potemkin Loader يُسلَّم باسم "avast_update" |
| Defense Evasion | Obfuscated Files or Information | T1027 | لودر reverse-base64 على omani-disputes.com/txt/ |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | اللودر يفك تشفير حمولته وقت التشغيل |
| Command and Control | Ingress Tool Transfer | T1105 | أرشيفات SmartLoader-MaaS تُسحب من raw.githubusercontent.com |
| Credential Access | Credentials from Password Stores | T1555 | مرحلة الجمع في PureLogsStealer |

---

## 6. الاستنتاجات الرئيسية | Key Judgments

- المؤشرات الخمسة ليست حملة واحدة. عائلات البرمجيات مختلفة (سارق، لودر،
  ClearFake، MaaS) والبنية التحتية موزّعة. التأطير الصحيح أنها **ظاهرة** لا
  **حملة**.
  الثقة: **عالية**. الأساس: عائلات متمايزة واستضافة غير مترابطة في الحالات
  الخمس، ولم يُعثر على أثر مشترك يعود لمشغل واحد.

- التسمية الخليجية طُعم لا دليل استهداف حصري للخليج — اتساقاً مع التصحيح
  التحليلي في التحقيق 002.
  الثقة: **متوسطة إلى عالية**. الأساس: البنية التحتية الفعلية في ألمانيا
  والولايات المتحدة، ولم يُرصد محتوى حمولة مخصص للخليج. وفي الحالتين المؤكدتين
  (قطر، عُمان) يبدو تبنّي الهوية الإقليمية متعمداً كطُعم.

- تكرار النمط (خمسة مؤشرات في ستة أسابيع، منها اثنان بتسمية خليجية مؤكدة) يبلغ وتيرة تستحق التتبع كمؤشر إنذار
  مبكر.
  الثقة: **متوسطة**. الأساس: نافذة رصد قصيرة ومصدرها منظومة جمع واحدة، وقد
  تعكس الوتيرة انحياز الجمع لا زيادة فعلية.

- مستودعا SmartLoader-MaaS كانا نشطين لحظة التحليل.
  الثقة: **عالية**. الأساس: سحب مباشر من الباحث، وبُلّغ GitHub Trust & Safety
  مع تأكيد استلام.

- QA-HOST-01 نطاق شرعي مخترق لا نطاق سجّله المهاجم.
  الثقة: **متوسطة**. الأساس: تاريخ تسجيل 2023 ومحتوى شرعي غير ذي صلة، ولم
  يُحصَّل أثر من جانب الخادم يؤكد مسار الاختراق.

### مقياس الثقة | Confidence Scale

عالية — مصادر مستقلة متعددة، أو رصد مباشر من الباحث.
متوسطة — أدلة متسقة، مع بدائل محتملة لم تُستبعد بالكامل.
منخفضة — مصدر واحد أو قرائن ظرفية؛ تُذكر كفرضية لا كنتيجة.

---

## 7. التوصيات

| الإجراء | الجهة | الأولوية |
|---------|-------|----------|
| إبلاغ عن مستودعي SmartLoader-MaaS | GitHub Trust & Safety | 🔴 عاجلة |
| إبلاغ عن omani-disputes.com | المركز الوطني للأمن السيبراني العُماني (mCERT) + NiceNIC abuse | 🟠 عالية |
| إبلاغ عن QA-HOST-01 [محجوب - REDACTED] | المركز الوطني القطري للأمن السيبراني + PDR abuse | 🟠 عالية |
| إضافة المؤشرات لقواعد الرصد المحلية | فرق SOC الخليجية | 🟡 متابعة |

---

## 8. ملاحق IOCs

انظر ملف `iocs_004_gulf_lures.txt` المرفق — يشمل النطاقات، الروابط الكاملة، العناوين IP، ومراجع URLhaus لكل مؤشر.

---

## 📋 سجل التصحيحات (2026-08-01 — v1.1)

- إعادة تصنيف `gulfbreezervrentals.com`: الاسم يعود لشركة تأجير بيوت متنقلة في مدينة Gulf Breeze بولاية فلوريدا الأمريكية، لا إلى الخليج العربي؛ استُبعد من عدّ التسمية الخليجية.
- حجب عنوان IP ومعرّفي URLhaus الخاصين بـ QA-HOST-01 — كان نشرها مع الحجب يجعل كشف هوية النطاق ممكناً، فأُزيلت التزاماً بسياسة الإفصاح المسؤول.
- توحيد موقف `shaggulf-sold.xyz` على الثقة المنخفضة في الجدول والملخص (تطابق لفظي لا دليل تسمية).
- تصحيح صف T1105: السحب من raw.githubusercontent.com لا من إصدارات GitHub (الإصدارات تخص التحقيق 002).

---

## ⚠️ إخلاء مسؤولية

تحليل دفاعي بحت. جميع المؤشرات من فيدات تهديدات مفتوحة المصدر (URLhaus, ThreatFox) وبيانات تسجيل عامة. لم يتم تشغيل أو تحميل أي عينة خبيثة. مستويات الثقة مصرح بها صراحة لكل استنتاج.
