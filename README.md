# Rafa Payment (Ziflazz) — Production Security Backend

Backend finansial dan payment gateway QRIS siap produksi (**Production-Ready**) menggunakan Node.js (Express) dengan arsitektur **Defense-in-Depth** untuk menangkal serangan DDoS, SQL/NoSQL Injection, XSS, CSRF, manipulasi transaksi (double-spending, price tampering, replay attacks), serta infeksi virus/malware.

---

## 🛡️ Matriks Arsitektur Keamanan (Defense in Depth)

| Kategori Ancaman | Mekanisme Pertahanan | Implementasi Teknis |
|---|---|---|
| **DDoS & Volumetric Attack** | `express-rate-limit` bertingkat + Payload Capping | • Global: 100 req / 15 min<br>• Create QR: 10 req / 5 min<br>• Webhook: 60 req / 1 min<br>• Strict Payload limit: **10kb** |
| **Reverse Proxy / Cloudflare** | Trust Proxy Configuration | `app.set('trust proxy', 1)` dengan ekstraksi IP asli dari header `CF-Connecting-IP` & `X-Forwarded-For`. |
| **SQL/NoSQL Injection & XSS** | `zod` Schema Validation + Prepared Statements | • Validasi tipe data ketat, batas angka (Rp 1.000 - Rp 50.000.000)<br>• Format `orderId` sanitasi regex `^[A-Za-z0-9_-]{8,64}$`<br>• Parameterized queries strictly bound. |
| **HTTP Header Attacks & Clickjacking** | `helmet` + `hpp` | • CSP ketat (default `'none'`, scripts `'self'`)<br>• HSTS preload & subdomains (31536000s)<br>• Frameguard `DENY`<br>• HPP (HTTP Parameter Pollution). |
| **Replay & Timing Attack (Webhook)** | HMAC SHA-256 + `crypto.timingSafeEqual` | Menggunakan byte stream mentah (`rawBody`) dan komparasi konstan waktu untuk mencegah Timing Side-Channel. |
| **Double Spending & Race Condition** | Idempotency Key Engine | `Idempotency-Key` dengan status `PROCESSING` (lock) dan `COMPLETED` (replay cache). Replikasi instan tanpa proses ulang. |
| **Price Tampering (Fraud)** | Authoritative Server Price Check | Server memeriksa database internal `order.amount === reportedAmount`. Jika tidak cocok, transaksi diblokir status `FRAUD_SUSPECT` dan memicu alert 422. |
| **Unauthorized Webhook Spoofing** | Gateway IP Whitelisting | Middleware memverifikasi IP pengirim callback hanya berasal dari pool IP resmi payment gateway. |
| **Malware / Web Shell Upload** | In-Memory Buffer + Magic Bytes + ClamAV | • Multer buffer (file tidak pernah menyentuh disk sebelum lolos)<br>• Verifikasi Magic Bytes byte-level (JPEG, PNG, PDF)<br>• Pemindaian virus real-time via `clamscan` TCP socket. |
| **Information Disclosure** | Centralized Error Sanitization | Tidak pernah membocorkan `stack trace` atau nama query ke klien publik. Setiap insiden diberi UUID unik (`errorId`). |

---

## 📂 Struktur Direktori

```text
ziflazz-backend/
├── src/
│   ├── config/
│   │   ├── env.js                  # Validasi variabel lingkungan via Zod (Fail-Fast)
│   │   └── database.js             # Layer DB dengan Parameterized Prepared Statements
│   ├── middlewares/
│   │   ├── rateLimiter.js          # Rate limiter bertingkat (global, qr, webhook)
│   │   ├── security.js             # Helmet CSP, HPP, CORS whitelist
│   │   ├── ipWhitelist.js          # Gateway IP whitelist & Cloudflare IP resolver
│   │   ├── idempotency.js          # Idempotency Key lock & replay engine
│   │   ├── validate.js             # Zod validation middleware untuk Express
│   │   ├── upload.js               # Multer memory storage & Magic Bytes inspection
│   │   └── errorHandler.js         # Production error handler (Masking stack traces)
│   ├── validators/
│   │   └── payment.validator.js    # Skema Zod untuk Order, Webhook, & Upload
│   ├── services/
│   │   ├── payment.service.js      # Logika HMAC timing-safe, rekonsiliasi harga, QRIS string
│   │   └── antivirus.service.js    # ClamAV INSTREAM socket scanner
│   ├── controllers/
│   │   └── payment.controller.js   # HTTP Request Orchestrator
│   ├── routes/
│   │   └── payment.routes.js       # Definisi rute dengan rantai middleware keamanan
│   └── app.js                      # Perakitan Express & rawBody capture
├── test/
│   └── security.test.js            # Automated security verification test suite (7 tests)
├── server.js                       # Graceful shutdown & lifecycle handler
├── package.json
├── .env.example
└── .env
```

---

## 🚀 Panduan Menjalankan & Menguji

### 1. Menjalankan Server
```bash
node server.js
```
Output:
```text
================================================================
🛡️  Rafa Payment (Ziflazz) Security Backend Online
📡  Listening on http://0.0.0.0:4000
🔒  Environment: DEVELOPMENT | Trust Proxy: 1
🛡️  Defense in Depth: Rate-Limiting, HMAC-SHA256, ClamAV, Zod Active
================================================================
```

### 2. Menjalankan Suite Uji Keamanan Otomatis
```bash
npm test
# atau
node --test test/security.test.js
```
Hasil:
```text
✔ 🛡️ Security Test 1: Anti-DDoS — Payload > 10kb rejected with 413
✔ 🛡️ Security Test 2: Anti-Injection — Zod validates bounds and safe IDs
✔ 🛡️ Security Test 3: Financial Security — Idempotency Key Replay
✔ 🛡️ Security Test 4: Financial Security — HMAC Webhook Tampering Interception
✔ 🛡️ Security Test 5: Financial Security — Webhook Amount Mismatch (Price Tampering)
✔ 🛡️ Security Test 6: Anti-Malware — Magic Bytes rejects spoofed file
✔ 🛡️ Security Test 7: Error Sanitization — 404 does not leak internal info
```
