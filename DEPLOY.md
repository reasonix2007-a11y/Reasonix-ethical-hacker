# نشر Reasonix على Railway (Docker + Kali Linux)

هذا المشروع يُبنى كحاوية Docker مبنية على **Kali Linux** (`kalilinux/kali-rolling`)
مع Node.js مثبّت فوقها، وتحتوي أدوات الفحص من مستودعات كالي الرسمية. يُنشر على
Railway والبناء يتم على سيرفرات Railway.

> Railway منصّة حاويات **لينكس فقط**: لا يوجد Windows CMD ولا WSL. الأدوات الرسومية
> (Burp، Maltego، Vega، IDA)، وأدوات ويندوز (x64dbg)، وأدوات اللاسلكي التي تحتاج
> محوّلاً فيزيائياً (aircrack، wifite، reaver)، والأدوات التجارية المرخّصة
> (Nessus، Qualys، Burp Pro) **لا يمكن تشغيلها هنا** ولم تُثبّت.

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
| `REASONIX_START_MOBSF` | `true` لتشغيل خدمة MobSF داخل الحاوية (ثقيلة) | اختياري |
| `REASONIX_TRUSTED_PROXY_IPS` | IP بروكسي Railway إن لزم تسجيل IP العميل | اختياري |
| `PORT` | يضبطه Railway تلقائيًا — لا تضعه يدويًا | — |

Railway يحقن `PORT` تلقائيًا؛ السيرفر يستمع عليه ويربط `0.0.0.0` في الإنتاج.

## 5) تخزين دائم (Persistent Volume)
بيانات المستخدمين المشفّرة تُكتب في `/app/data`. أضف Volume على Railway بنقطة
تثبيت `/app/data` حتى لا تُمسح البيانات عند إعادة النشر.

## 6) ملاحظات حول الحجم والبناء
الحاوية تثبّت حزم كالي (`kali-tools-*`) + أدوات إضافية: metasploit، exploitdb
(searchsploit)، nmap، nikto، sqlmap، wpscan، hydra، john، radare2، binwalk،
tshark، nuclei، httpx، subfinder، katana، dnsx، naabu، gobuster، ffuf، amass،
dalfox، trivy، grype، gitleaks، trufflehog، semgrep، checkov، OWASP ZAP وغيرها.

الحجم كبير جدًا (عدة GB، ربما 6–10GB+). ملاحظات مهمة:
- كل تثبيت أداة **متسامح مع الفشل** (`|| echo FAILED`): فشل حزمة واحدة يُسجَّل في
  سجلّ البناء ولا يُجهض الصورة؛ الأداة المفقودة تبقى ظاهرة كـ"غير مثبتة" في الواجهة.
- الأعطال الصلبة الوحيدة التي تُفشل البناء: طبقة apt الأساسية، تثبيت Node، `npm ci`،
  أو **تجاوز مهلة/سقف خطة Railway**. راقب سجلّ البناء في لوحة Railway.
- الأدوات التي تحتاج خدمات (ZAP، sqlmap API، MobSF) تبدأ من `docker-entrypoint.sh`
  وتزيد استهلاك الذاكرة؛ ZAP يبدأ فقط عند ضبط `REASONIX_ZAP_API_KEY`، وMobSF فقط عند
  `REASONIX_START_MOBSF=true`.

## 6.1) ما لا يعمل على Railway (مقصود)
- أدوات رسومية GUI: Burp، Vega، Maltego، Cutter، IDA.
- أدوات ويندوز: x64dbg.
- أدوات لاسلكي تحتاج محوّل شبكة فيزيائي: aircrack-ng، wifite، reaver، kismet، bettercap.
- خدمات تجارية مرخّصة أو تحتاج مفاتيح حساب: Nessus، Qualys، Burp Pro، Shodan، Censys، Snyk.

## 7) ضوابط التفويض
في الإنتاج، الفحوصات مرفوضة حتى يُضبط `REASONIX_TENANT_ID` و
`REASONIX_ALLOWED_DOMAINS`. لا تفحص إلا أصولًا تملك تفويضًا كتابيًا بفحصها.
