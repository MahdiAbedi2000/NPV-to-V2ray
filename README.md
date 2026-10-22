# 🛡️ NPV//FORGE — NPV Tunnel to V2Ray Decryptor & Universal Converter

<div align="center">

**سامانه تخصصی و کلاینت‌ساید رمزگشایی، تبدیل و بازنویسی کانتینرهای NPV Tunnel به V2Ray / Xray / Sing-box / Clash**

[![Deploy to Cloudflare Pages](https://img.shields.io/badge/Deploy-Cloudflare%20Pages-f38020?style=for-the-badge&logo=cloudflare)](https://pages.cloudflare.com/)
[![React 19](https://img.shields.io/badge/React-19.0-61dafb?style=for-the-badge&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178c6?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

[🌐 مشاهده پیش‌نمایش زنده](https://npv-forge.pages.dev) • [📖 راهنمای استقرار](./DEPLOY.md)

</div>

---

## 📌 معرفی پروژه (Overview)

پروژه **NPV//FORGE** یک وب‌اپلیکیشن مستقل (SPA) جهت بازگشایی و رمزگشایی کانتینرهای قفل‌شده نرم‌افزار **NapsternetV** و پروتکل‌های **NPV Tunnel** است. این ابزار به صورت **۱۰۰٪ کلاینت‌ساید (Client-Side)** مستقیماً روی پردازنده دستگاه کاربر اجرا شده و تمامی الگوریتم‌های رمزنگاری وایت‌باکس (White-Box AES-CTR و ChaCha20-Poly1305) را بدون ارسال حتی یک بایت داده به سرور به انجام می‌رساند.

### ✨ ویژگی‌های کلیدی (Key Features)

- **رمزگشایی چندنسلی:**
  - کانتینرهای باینری نسل ۵ (`NPVS v5` / Gen-2 White-Box)
  - کانتینرهای متنی نسل ۴ (`NPVT1` / v4 AES-CTR)
  - کانتینرهای باز و توکن‌های پایگاه `NPVO1`، `NetMod (.nm)` و رشته‌های Base64
- **تولید خروجی‌های چندگانه و استاندارد:**
  - لینک‌های مستقیم `vless://`، `vmess://`، `trojan://` و `ss://`
  - رشته اشتراک استاندارد Base64 جهت درج در v2rayNG و سایر کلاینت‌ها
  - خروجی ساختاریافته **Xray JSON** با outbounds تفکیک‌شده
  - خروجی بهینه‌سازی‌شده برای هسته **Sing-box**
  - خروجی کانفیگ پروکسی برای **Clash Meta / Mihomo**
- **فضای آرشیو و ذخیره محلی (Config Library):**
  - امکان ذخیره گره‌های هر فایل و خالی کردن ورودی جهت استخراج پی‌درپی کانفیگ بعدی
  - تجمیع خودکار و امکان رونویسی یا بارگیری یکپارچه تمامی سرورها در یک فایل واحد
- **تثبیت خودکار گواهی امنیتی Fastly (x509 Auto-Fix):**
  - تشخیص خودکار تداخل گواهی در Endpointهای شبکه Fastly CDN و تزریق هوشمند پارامترهای `allowInsecure=1` و `vcn=default.ssl.fastly.net`
- **فرآیند معکوس (NPV Container Builder):**
  - تبدیل لینک‌های خام V2Ray به کانتینرهای رمزنگاری‌شده `.npvs` و `.npvt`
- **استودیوی اختصاصی بازنویسی و برندینگ:**
  - تغییر نام دسته‌ای سرورها با الگوهای شماره‌گذاری و متغیرهای پویا
  - حذف خودکار شناسه‌های تلگرام و تبلیغات فروشندگان پیشین
  - تنظیم پست آماده انتشار همراه با هدر و پاورقی اختصاصی
- **امنیت و حریم خصوصی مطلق (Zero-Telemetry):**
  - صفر بایت ارتباط سروری؛ کلیه فرآیندها به صورت آفلاین درون مرورگر انجام می‌پذیرد.

---

## 🚀 راه‌اندازی و اجرای لوکال (Local Setup)

### پیش‌نیازها
- **Node.js** نسخه 18 یا بالاتر
- **npm** یا **pnpm** یا **bun**

### مراحل اجرا:
```bash
# ۱. کلون کردن ریپازیتوری
git clone https://github.com/your-username/npv-to-v2ray.git
cd npv-to-v2ray

# ۲. نصب وابستگی‌ها
npm install

# ۳. اجرای سرور توسعه محلی
npm run dev
```

برنامه روی آدرس پیش‌فرض `http://localhost:3000` در دسترس خواهد بود.

### اجرای تست‌های واحد (Unit Tests):
```bash
npm test
```
*شامل ۱۵ تست یکپارچه اعتبارسنجی الگوریتم‌های رمزنگاری White-Box، کانتینرهای Gen-2، ChaCha20 و توابع تبدیل پروتکل‌ها.*

### بیلد نهایی جهت استقرار (Production Build):
```bash
npm run build
```
خروجی فشرده و بهینه‌سازی‌شده در دایرکتوری `dist/` ایجاد می‌گردد.

---

## ☁️ استقرار روی Cloudflare Pages (رایگان)

این سامانه به صورت یک برنامه کاملاً استاتیک (SPA) توسعه یافته است و به طور کامل با پلن رایگان **Cloudflare Pages** هماهنگ می‌باشد (بدون نیاز به توابع سروری یا مصرف ورکر).

### روش ۱: استقرار خودکار با اتصال به GitHub (پیشنهادی)
1. ریپازیتوری خود را در **GitHub** پوش نمایید.
2. در داشبورد کلادفلر به مسیر **Workers & Pages > Create > Pages > Connect to Git** بروید.
3. تنظیمات بیلد را مطابق مقادیر زیر وارد فرمایید:
   - **Framework preset:** `Vite`
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
   - **Environment variables:** متغیر `NODE_VERSION` با مقدار `20`
4. بر روی دکمه **Save and Deploy** کلیک فرمایید.

### روش ۲: استقرار مستقیم با Wrangler CLI
```bash
# لاگین به حساب کاربری کلادفلر (در صورت عدم لاگین پیشین)
npx wrangler login

# استقرار دایرکتوری dist
npm run deploy
```

---

## 📂 ساختار دایرکتوری پروژه (Project Structure)

```
├── public/                 # فایل‌های استاتیک، آیکون‌ها و کانفیگ‌های هاستینگ
│   ├── _headers            # هدرهای امنیتی و کش پایدار شبکه Anycast
│   ├── _redirects          # هدایت مسیرهای SPA به index.html
│   ├── favicon.svg         # آیکون وکتور مدرن سامانه
│   ├── site.webmanifest    # مانیفست وب‌اپلیکیشن
│   └── assets/npvs/        # جداول باینری وایت‌باکس (Gen-2 Tables)
├── src/
│   ├── components/         # کامپوننت‌های رابط کاربری
│   │   ├── Brand.tsx       # نشان تجاری، لوگوتایپ و سوییچر تم
│   │   ├── ConfigLibrary.tsx # فضای آرشیو و ادغام کانفیگ‌های استخراج‌شده
│   │   ├── InteractiveTour.tsx # تور راهنمای تعاملی گام‌به‌گام
│   │   ├── NetworkPingTester.tsx # ابزار سنجش تاخیر زمانی و اتصال
│   │   ├── NodeModal.tsx   # نمایش مشخصات، بارکد QR و خروجی‌های هر گره
│   │   ├── StageFlow.tsx   # گام‌بندی و مراحل پیش‌رونده
│   │   ├── StealthRebrandStudio.tsx # استودیوی بازنویسی و انتشار
│   │   ├── VaultGate.tsx   # دروازه امنیتی استودیوی اختصاصی
│   │   ├── WelcomeGuide.tsx # پنجره راهنمای سریع
│   │   ├── XrayLogDiagnostic.tsx # عیب‌یاب خطاهای TLS در لاگ Xray
│   │   └── ui.tsx          # کامپوننت‌های پایه (مودال، دکمه رونویسی، نشانگر پینگ)
│   ├── utils/              # توابع محاسباتی، رمزگشایی و تبدیل پروتکل
│   │   ├── npvConverter.ts # هسته اصلی تبدیل فرمت‌ها و تزریق TLS
│   │   ├── npvsDecryptor.ts # رمزگشای White-Box کانتینرهای NPVS
│   │   ├── npvCryptV5.ts   # توابع رمزنگاری کانتینرهای نسل ۵
│   │   └── vaultCrypto.ts  # الگوریتم‌های اعتبارسنجی هش محلی
│   ├── App.tsx             # کامپوننت اصلی و هماهنگ‌کننده سامانه
│   ├── index.css           # سیستم طراحی، متغیرهای تم ابسیدین و انیمیشن‌ها
│   └── main.tsx            # نقطه ورودی برنامه
├── package.json
├── tsconfig.json
├── vite.config.ts
└── wrangler.toml
```

---

## 🔒 امنیت و انطباق (Security & Privacy)

- **بدون ذخیره‌سازی داده:** هیچ‌گونه لاگ، نشانی IP یا محتوای کانفیگ به هیچ سرور خارجی ارسال نمی‌شود.
- **پردازش درون‌حافظه‌ای:** تمام داده‌ها در حافظه موقت رم دستگاه کاربر پردازش شده و در صورت تمایل کاربر در `localStorage` همان دستگاه نگهداری می‌گردد.
- **استفاده مسئولانه:** این سامانه صرفاً جهت تسهیل مهاجرت و مدیریت کانفیگ‌های ارتباطی کاربر طراحی گردیده است.

---

## 📄 مجوز انتشار (License)

این پروژه تحت مجوز [MIT License](LICENSE) منتشر شده است. استفاده آزاد با رعایت حق نسخه اصلی مجاز می‌باشد.
