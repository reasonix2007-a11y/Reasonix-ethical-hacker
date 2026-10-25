# نشر Reasonix على Railway (Docker + Linux)

هذا المشروع يُبنى كحاوية Docker على لينكس تحتوي كامل أدوات الفحص، ويُنشر على
Railway. البناء يتم على سيرفرات Railway.

## 1) المتطلبات
- حساب GitHub: `reasonix2007-a11y` (لرفع الكود).
- حساب Railway (مربوط بنفس بريد GitHub يسهّل الربط).

## 2) رفع الكود إلى GitHub
أنشئ مستودعًا جديدًا تحت الحساب `reasonix2007-a11y` باسم مثل `reasonix`،
ثم اربط المستودع المحلي به ورفع الفرع `main`.

> ملاحظة: الـ `origin` الحالي مربوط بمستودع آخر (`nashmi-ride-web`) — يجب تغييره.

## 3) إنشاء المشروع على Railway
1. New Project → Deploy from GitHub repo → اختر مستودع `reasonix`.
2. Railway يقرأ `railway.json` ويبني عبر `Dockerfile` تلقائيًا.

## 4) المتغيّرات (Variables / Secrets) — إلزامية
في Railway: Service → Variables، أضف:

| المتغيّر | القيمة | إلزامي |
|---|---|---|
| `REASONIX_DATA_KEY` | مفتاح عشوائي 64 hex (مولّد أدناه) | ✅ |
| `REASONIX_TENANT_ID` | معرّف المؤسسة، مثل `your-org` | ✅ (الإنتاج) |
| `REASONIX_ALLOWED_DOMAINS` | النطاقات المصرّح بفحصها، مثل `example.com,example.org` | ✅ (الإنتاج) |
| `REASONIX_ZAP_API_KEY` | مفتاح عشوائي لتفعيل ZAP daemon | اختياري |
| `REASONIX_TRUSTED_PROXY_IPS` | IP بروكسي Railway إن لزم تسجيل IP العميل | اختياري |
| `PORT` | يضبطه Railway تلقائيًا — لا تضعه يدويًا | — |

Railway يحقن `PORT` تلقائيًا؛ السيرفر يستمع عليه ويربط `0.0.0.0` في الإنتاج.

## 5) تخزين دائم (Persistent Volume)
بيانات المستخدمين المشفّرة تُكتب في `/app/data`. أضف Volume على Railway بنقطة
تثبيت `/app/data` حتى لا تُمسح البيانات عند إعادة النشر.

## 6) ملاحظات حول الحجم
الحاوية تثبّت كل الأدوات (nmap, nuclei, httpx, subfinder, katana, dnsx, naabu,
gobuster, ffuf, amass, assetfinder, sqlmap, wapiti, theHarvester, sublist3r,
wpscan, nikto, whatweb, sslscan, wafw00f, wfuzz, testssl.sh, OWASP ZAP).
الحجم كبير (عدة GB). إذا تجاوز سقف خطة Railway وفشل البناء، نقلّل الأدوات.

## 7) ضوابط التفويض
في الإنتاج، الفحوصات مرفوضة حتى يُضبط `REASONIX_TENANT_ID` و
`REASONIX_ALLOWED_DOMAINS`. لا تفحص إلا أصولًا تملك تفويضًا كتابيًا بفحصها.
