import hashlib
import logging
import os
import re
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from html import unescape
from urllib.parse import urlparse

from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

LOCAL_HOSTS = {"localhost", "127.0.0.1"}

CFG = {
    "DEFAULT_SUBJECT": os.getenv("DEFAULT_SUBJECT", "New Contact Form Submission"),
    # Support a comma/semicolon-separated allowlist while still accepting the
    # older single-origin variable name for backwards compatibility.
    "ALLOWED_ORIGINS": os.getenv("ALLOWED_ORIGINS", os.getenv("ALLOWED_ORIGIN", "")).strip(),
    "SMTP_EMAIL": os.getenv("SMTP_EMAIL", "").strip(),
    "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", "").strip(),
    "RECEIVER_EMAILS": os.getenv("RECEIVER_EMAILS", os.getenv("RECEIVER_EMAIL", "")).strip(),
    "TRUST_PROXY_COUNT": int(os.getenv("TRUST_PROXY_COUNT", "0")),
    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO").strip() or "INFO",
    "MAX_BODY_BYTES": 8192,
    "REPLAY_TTL": 300,
    "FAILURE_TTL": 900,
    "FAILURE_THRESHOLD": 3,
    "COOLDOWN_TTL": 900,
}
REQUIRED = ("ALLOWED_ORIGINS", "SMTP_EMAIL", "SMTP_PASSWORD", "RECEIVER_EMAILS")
MISSING = [key for key in REQUIRED if not CFG[key]]
if MISSING:
    raise RuntimeError(f"Missing env vars: {', '.join(MISSING)}")
if CFG["TRUST_PROXY_COUNT"] < 0:
    raise RuntimeError("TRUST_PROXY_COUNT must be 0 or greater")


def normalize_site(url, *, label, allow_root_path):
    parsed = urlparse(url or "")
    if not parsed.scheme or not parsed.hostname:
        raise RuntimeError(f"{label} must include a scheme and hostname")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise RuntimeError(f"{label} must not include credentials, params, query, or fragment")
    if parsed.path and (parsed.path != "/" or not allow_root_path):
        raise RuntimeError(f"{label} must be an origin, not a full URL path")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    if scheme not in {"https", "http"}:
        raise RuntimeError(f"{label} must use http or https")
    if scheme != "https" and host not in LOCAL_HOSTS:
        raise RuntimeError(f"{label} must be HTTPS outside local development")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise RuntimeError(f"{label} has an invalid port") from exc
    return scheme, host, port


def format_origin(site):
    scheme, host, port = site
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


allowed_sites = []
for item in re.split(r"[;,]", CFG["ALLOWED_ORIGINS"]):
    value = item.strip()
    if not value:
        continue
    site = normalize_site(value, label="ALLOWED_ORIGINS", allow_root_path=True)
    if site not in allowed_sites:
        allowed_sites.append(site)
if not allowed_sites:
    raise RuntimeError("ALLOWED_ORIGINS must contain at least one valid origin")
CFG["ALLOWED_ORIGINS"] = tuple(format_origin(site) for site in allowed_sites)
CFG["ALLOWED_SITES"] = frozenset(allowed_sites)
CFG["SMTP_EMAIL"] = validate_email(CFG["SMTP_EMAIL"], check_deliverability=False, allow_smtputf8=False).normalized.lower()
receivers = []
for item in re.split(r"[;,]", CFG["RECEIVER_EMAILS"]):
    value = item.strip().lower()
    if not value:
        continue
    normalized = validate_email(value, check_deliverability=False, allow_smtputf8=False).normalized.lower()
    if normalized not in receivers:
        receivers.append(normalized)
if not receivers:
    raise RuntimeError("RECEIVER_EMAILS must contain at least one valid email")
if len(receivers) > 20:
    raise RuntimeError("RECEIVER_EMAILS supports at most 20 recipients")
CFG["RECEIVER_EMAILS"] = receivers

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = CFG["MAX_BODY_BYTES"]
if CFG["TRUST_PROXY_COUNT"]:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=CFG["TRUST_PROXY_COUNT"], x_proto=CFG["TRUST_PROXY_COUNT"])
logging.basicConfig(level=CFG["LOG_LEVEL"], format="%(asctime)s %(levelname)s %(message)s")
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[], storage_uri="memory://")

# Redis was removed, so abuse controls are in-memory only. Keep production to one
# process or the rate limits, cooldowns, and replay protection will split by worker.
MEMORY, LOCK = {}, threading.Lock()
TAG_RE = re.compile(r"<[^>\n]{0,500}>")
PHONE_RE = re.compile(r"^[0-9+().\-\s]{5,20}$")
FIELDS = {"name", "email", "phone", "subject", "message"}


def sweep():
    now = time.time()
    with LOCK:
        for key, (_, exp) in list(MEMORY.items()):
            if exp <= now:
                MEMORY.pop(key, None)
    return now


def ttl(key):
    now = sweep()
    with LOCK:
        return max(int(MEMORY.get(key, ("", 0))[1] - now), 0)


def add_once(key, ttl_seconds):
    now = sweep()
    with LOCK:
        if key in MEMORY:
            return False
        MEMORY[key] = ("1", now + ttl_seconds)
        return True


def incr(key, ttl_seconds):
    now = sweep()
    with LOCK:
        value, exp = MEMORY.get(key, (0, now))
        if exp <= now:
            value = 0
        value += 1
        MEMORY[key] = (value, now + ttl_seconds)
        return value


def delete(key):
    with LOCK:
        MEMORY.pop(key, None)


def site_from_url(url):
    parsed = urlparse(url or "")
    if not parsed.scheme or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def allowed_request_origin():
    origin = request.headers.get("Origin", "")
    if not origin:
        return "", None
    try:
        site = normalize_site(origin, label="Origin", allow_root_path=False)
    except RuntimeError:
        return origin, None
    if site not in CFG["ALLOWED_SITES"]:
        return origin, None
    return origin, site


def respond(payload, status):
    response = app.response_class(status=status) if status == 204 else jsonify(payload)
    response.status_code = status
    origin, origin_site = allowed_request_origin()
    if origin_site:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Max-Age"] = "600"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Vary"] = "Origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def reject(ip, status, reason, count_failure=False):
    if count_failure and ip:
        if incr(f"fail:{ip}", CFG["FAILURE_TTL"]) >= CFG["FAILURE_THRESHOLD"]:
            add_once(f"cooldown:{ip}", CFG["COOLDOWN_TTL"])
    logging.warning("mailer_rejected ip=%s reason=%s", ip, reason)
    return respond({"error": "rate_limited" if status == 429 else "request_rejected"}, status)


def clean_text(value, max_len, multiline=False):
    if not isinstance(value, str):
        raise ValueError
    raw = unescape(value).strip()
    if not multiline and any(ch in raw for ch in ("\r", "\n", "\u2028", "\u2029", "\x85")):
        raise ValueError
    raw = TAG_RE.sub("", raw.replace("\r\n", "\n").replace("\r", "\n"))
    raw = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw)
    raw = re.sub(r"\s+", " ", raw).strip() if not multiline else re.sub(r"\n{3,}", "\n\n", raw).strip()
    if not raw or len(raw) > max_len:
        raise ValueError
    return raw


def parse_payload(data):
    if not isinstance(data, dict) or set(data) - FIELDS or any(key not in data for key in ("name", "email", "phone", "message")):
        raise ValueError
    email = clean_text(data["email"], 254).lower()
    email = validate_email(email, check_deliverability=False, allow_smtputf8=False).normalized.lower()
    subject_in = data.get("subject")
    subject = CFG["DEFAULT_SUBJECT"] if not isinstance(subject_in, str) or not subject_in.strip() else clean_text(subject_in, 150)
    payload = {
        "name": clean_text(data["name"], 100),
        "email": email,
        "phone": clean_text(data["phone"], 20),
        "subject": subject,
        "message": clean_text(data["message"], 1000, multiline=True),
    }
    if not PHONE_RE.fullmatch(payload["phone"]):
        raise ValueError
    return payload


def request_ok():
    _, origin_site = allowed_request_origin()
    if not origin_site:
        return 403, "origin"
    if origin_site[1] not in LOCAL_HOSTS and site_from_url(request.headers.get("Referer", "")) != origin_site:
        return 403, "referer"
    if not request.headers.get("User-Agent", "").strip():
        return 403, "user_agent"
    accept = request.headers.get("Accept", "*/*")
    if "application/json" not in accept and "*/*" not in accept:
        return 406, "accept"
    if request.mimetype != "application/json":
        return 415, "content_type"
    return 200, "ok"


def send_email(payload):
    msg = EmailMessage()
    msg["From"] = CFG["SMTP_EMAIL"]
    msg["To"] = "undisclosed-recipients:;"
    # Use Bcc so internal recipient addresses are not disclosed to one another.
    msg["Bcc"] = ", ".join(CFG["RECEIVER_EMAILS"])
    msg["Reply-To"] = payload["email"]
    msg["Subject"] = payload["subject"]
    # Plain-text only keeps untrusted input out of HTML rendering paths.
    msg.set_content(
        "New contact form submission\n\n"
        f"Name: {payload['name']}\n"
        f"Email: {payload['email']}\n"
        f"Phone: {payload['phone']}\n"
        f"Subject: {payload['subject']}\n\n"
        f"Message:\n{payload['message']}\n"
    )
    # TLS is mandatory so Gmail credentials are never sent in cleartext.
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(CFG["SMTP_EMAIL"], CFG["SMTP_PASSWORD"])
        smtp.send_message(msg)


@app.route("/send-mail", methods=["OPTIONS"])
def preflight():
    _, origin_site = allowed_request_origin()
    if not origin_site:
        return respond({"error": "forbidden"}, 403)
    requested_method = request.headers.get("Access-Control-Request-Method", "").upper()
    requested_headers = {item.strip().lower() for item in request.headers.get("Access-Control-Request-Headers", "").split(",") if item.strip()}
    if requested_method and requested_method != "POST":
        return respond({"error": "forbidden"}, 403)
    if requested_headers - {"content-type"}:
        return respond({"error": "forbidden"}, 403)
    return respond({}, 204)


@app.post("/send-mail")
@limiter.limit("10 per hour")
@limiter.limit("3 per minute")
def send_mail():
    ip = request.remote_addr or "unknown"
    cooldown = ttl(f"cooldown:{ip}")
    if cooldown:
        logging.warning("mailer_cooldown ip=%s ttl=%s", ip, cooldown)
        return respond({"error": "rate_limited"}, 429)
    status, reason = request_ok()
    if status != 200:
        return reject(ip, status, reason)
    data = request.get_json(silent=True)
    try:
        payload = parse_payload(data)
    except (ValueError, EmailNotValidError):
        return reject(ip, 400, "validation", count_failure=True)
    replay_key = "replay:" + hashlib.sha256(f"{payload['name']}|{payload['email']}|{payload['phone']}|{payload['subject']}|{payload['message']}".encode()).hexdigest()
    # Duplicate suppression limits double-click resubmits and cheap replay spam.
    if not add_once(replay_key, CFG["REPLAY_TTL"]):
        return reject(ip, 409, "replay", count_failure=True)
    try:
        send_email(payload)
        delete(f"fail:{ip}")
        logging.info("mailer_sent ip=%s", ip)
        return respond({"status": "ok"}, 200)
    except Exception as exc:
        delete(replay_key)
        logging.exception("mailer_failed ip=%s error=%s", ip, exc.__class__.__name__)
        return respond({"error": "mail_unavailable"}, 503)


@app.errorhandler(413)
def too_large(_):
    return respond({"error": "payload_too_large"}, 413)


@app.errorhandler(429)
def limited(_):
    logging.warning("mailer_rate_limited ip=%s", request.remote_addr or "unknown")
    return respond({"error": "rate_limited"}, 429)


@app.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, HTTPException):
        return respond({"error": "request_rejected"}, exc.code or 400)
    logging.exception("mailer_server_error ip=%s error=%s", request.remote_addr or "unknown", exc.__class__.__name__)
    return respond({"error": "server_error"}, 500)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
