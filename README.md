# 🚀 Lightweight Secure Mailer API (Flask)

A minimal, production-oriented Flask API for sending contact-form emails via Gmail SMTP. Designed with strict validation, origin checks, rate limiting, and safe email handling.

> ⚠️ **Important**
> This version does **NOT** include CAPTCHA or Redis. Abuse resistance is best-effort only.
> For strong protection, add CAPTCHA or a backend relay.

---

## ✨ Features

* Single endpoint: `POST /send-mail`
* Sends email via Gmail SMTP (App Password)
* Supports multiple recipients (hidden via BCC)
* Strict input validation & sanitization
* Origin + Referer enforcement
* Rate limiting + replay protection
* Plain-text email (no HTML injection risk)
* No sensitive data logging

---

## 📦 Requirements

* Python 3.11+
* Gmail account with 2FA enabled
* Gmail App Password
* Single-process deployment (no multi-worker without shared state)

---

## ⚙️ Setup Guide

### 1. Create virtual environment

```bash
python -m venv .venv
```

### 2. Activate it

```bash
# Windows
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
```

Edit `.env` with real values.

### 5. Run locally

```bash
flask --app app run
```

API will be available at:

```
http://127.0.0.1:5000/send-mail
```

---

## 🔐 Environment Variables

| Variable            | Required | Description                      |
| ------------------- | -------- | -------------------------------- |
| `DEFAULT_SUBJECT`   | No       | Default subject fallback         |
| `ALLOWED_ORIGINS`   | Yes      | Comma-separated allowed frontend origins |
| `SMTP_EMAIL`        | Yes      | Gmail sender email               |
| `SMTP_PASSWORD`     | Yes      | Gmail App Password               |
| `RECEIVER_EMAILS`   | Yes      | Comma-separated recipient emails |
| `TRUST_PROXY_COUNT` | No       | Number of trusted proxies        |
| `LOG_LEVEL`         | No       | Logging level                    |

---

## 📥 Request Format

```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "phone": "+1 555 555 5555",
  "subject": "Project inquiry",
  "message": "Hello, I would like to discuss a build."
}
```

### Rules

* `name`: required, max 100 chars
* `email`: required, normalized lowercase
* `phone`: required, max 20 chars
* `subject`: optional (defaults automatically)
* `message`: required, max 1000 chars
* Recipients are **server-side only**

---

## 🌐 Frontend Example

```javascript
async function sendContactForm(payload) {
  const response = await fetch("https://api.example.com/send-mail", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify(payload),
    credentials: "omit"
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "request_failed");
  }
  return data;
}
```

> ⚠️ Do not strip the `Referer` header — it is used for security checks.

---

## 🛡️ Security Controls

* Strict CORS (exact allowlist)
* Origin + Referer validation
* Reject missing `User-Agent`
* Enforce `application/json`
* Schema validation (reject unknown fields)
* CRLF injection protection
* Plain-text emails only
* BCC delivery (no recipient leakage)
* Rate limiting (`flask-limiter`)
* Replay protection (duplicate blocking)
* In-memory cooldown for abuse
* No sensitive logs

---

## 🚀 Production Deployment

Run with **single worker**:

```bash
gunicorn --workers 1 --threads 8 --bind 0.0.0.0:8000 app:app
```

### Recommended Setup

* Use Nginx (or similar) as reverse proxy
* Enable HTTPS
* Forward real client IP
* Set `TRUST_PROXY_COUNT` correctly
* Store secrets securely (env or secret manager)

---

## 📊 Response Codes

| Status | Meaning                  |
| ------ | ------------------------ |
| `200`  | Success                  |
| `400`  | Validation failed        |
| `403`  | Origin / header rejected |
| `406`  | Client must accept JSON  |
| `409`  | Duplicate request        |
| `413`  | Payload too large        |
| `415`  | Invalid content type     |
| `429`  | Rate limit triggered     |
| `503`  | Email delivery failed    |

---

## ⚠️ Known Limitations

* No CAPTCHA → weaker bot protection
* No Redis → limits are per-process only
* Origin/Referer can be spoofed outside browsers
* Public API = always attackable

---

## 🔧 Hardening Checklist

* Use HTTPS
* Set exact `ALLOWED_ORIGINS` values
* Use Gmail App Password (never real password)
* Keep recipients server-side only
* Monitor logs for abuse
* Rotate credentials if needed
* Add CAPTCHA for stronger protection
* Consider backend relay for full security

---

## 🧠 Summary

This API is:

* ✅ Lightweight
* ✅ Minimal
* ✅ Secure *for its constraints*

But:

> It is still a **public endpoint** — treat it as such.

---

## 📌 Future Improvements

* Add CAPTCHA (recommended)
* Add Redis for distributed rate limiting
* Add signed requests / tokens
* Move behind backend proxy

---

## 🪪 License

MIT (or your choice)
