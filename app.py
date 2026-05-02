"""
Phishing Detector - Strong Flask Backend
Features:
  - Multi-layer URL analysis engine
  - Rate limiting (per IP)
  - Request logging
  - Input validation & sanitization
  - Weighted risk scoring (100-point scale)
  - Threat intelligence patterns
  - JSON API + HTML form support
  - Security headers
"""

from flask import Flask, render_template, request, jsonify, abort
from urllib.parse import urlparse
import re
import time
import ipaddress
import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

# ─── Rate Limiter (in-memory, per IP) ────────────────────────────────────────
RATE_LIMIT = 20        # max requests
RATE_WINDOW = 60       # per 60 seconds
_rate_store = defaultdict(list)

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        return True
    _rate_store[ip].append(now)
    return False

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE = "scan_logs.jsonl"

def log_scan(ip: str, url: str, result: dict):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip_hash": hashlib.sha256(ip.encode()).hexdigest()[:12],
        "url_hash": hashlib.sha256(url.encode()).hexdigest()[:16],
        "score": result.get("score"),
        "verdict": result.get("verdict"),
        "flags": result.get("flags", [])
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ─── Threat Intelligence Patterns ────────────────────────────────────────────

# High-risk keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "account", "password",
    "confirm", "banking", "paypal", "amazon", "google",
    "apple", "microsoft", "netflix", "support", "helpdesk",
    "suspended", "unusual", "alert", "notification", "reset",
    "recover", "unlock", "validate", "authorize", "credential",
    "wallet", "bitcoin", "crypto", "prize", "winner", "claim",
    "urgent", "limited", "expire", "free", "gift", "reward"
]

# Brands often impersonated in phishing
BRAND_NAMES = [
    "paypal", "amazon", "ebay", "google", "apple", "microsoft",
    "facebook", "instagram", "twitter", "netflix", "dropbox",
    "linkedin", "whatsapp", "yahoo", "outlook", "office365",
    "chase", "wellsfargo", "citibank", "bankofamerica", "hsbc",
    "dhl", "fedex", "ups", "usps", "irs", "gov"
]

# Suspicious TLDs often used for phishing
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".xyz", ".top", ".click", ".loan", ".work",
    ".party", ".review", ".science", ".faith",
    ".download", ".racing", ".date", ".win", ".bid"
]

# Known safe TLDs (reduce false positives)
TRUSTED_TLDS = [".com", ".org", ".edu", ".gov", ".net", ".io", ".co.uk"]

# ─── Analysis Engine ──────────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Multi-layer phishing analysis.
    Returns score (0-100), verdict, checks list, and flags.
    """
    checks = []
    flags = []
    total_score = 0

    # ── Normalize URL ──
    raw = url.strip()
    if not re.match(r'^https?://', raw, re.I):
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
        domain = parsed.netloc.lower().replace("www.", "")
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = raw.lower()
    except Exception:
        return {
            "score": 100, "verdict": "Phishing", "error": "Invalid URL",
            "checks": [{"label": "Invalid URL", "ok": False}], "flags": ["INVALID_URL"]
        }

    # ── 1. HTTPS Check (10 pts) ──
    has_https = raw.lower().startswith("https://")
    checks.append({"label": "HTTPS Secure" if has_https else "No HTTPS (HTTP)", "ok": has_https})
    if not has_https:
        total_score += 10
        flags.append("NO_HTTPS")

    # ── 2. IP Address as Host (25 pts) ──
    is_ip = False
    try:
        host = parsed.hostname or ""
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    checks.append({"label": "Domain Name OK" if not is_ip else "IP Address URL", "ok": not is_ip})
    if is_ip:
        total_score += 25
        flags.append("IP_AS_HOST")

    # ── 3. Suspicious TLD (15 pts) ──
    has_bad_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    checks.append({"label": "Clean TLD" if not has_bad_tld else "Suspicious TLD", "ok": not has_bad_tld})
    if has_bad_tld:
        total_score += 15
        flags.append("SUSPICIOUS_TLD")

    # ── 4. Phishing Keywords in URL (20 pts) ──
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full]
    has_keywords = len(found_keywords) > 0
    checks.append({"label": "No Phishing Keywords" if not has_keywords else f"Keywords: {', '.join(found_keywords[:3])}", "ok": not has_keywords})
    if has_keywords:
        # Scale: 1 keyword = 8pts, 2 = 14pts, 3+ = 20pts
        total_score += min(20, 8 + (len(found_keywords) - 1) * 6)
        flags.append("PHISHING_KEYWORDS")

    # ── 5. Brand Impersonation (20 pts) ──
    found_brands = [b for b in BRAND_NAMES if b in domain and not domain.endswith(f".{b}.com")]
    is_impersonating = bool(found_brands)
    checks.append({"label": "No Brand Impersonation" if not is_impersonating else f"Impersonates: {found_brands[0]}", "ok": not is_impersonating})
    if is_impersonating:
        total_score += 20
        flags.append("BRAND_IMPERSONATION")

    # ── 6. Excessive Subdomains (10 pts) ──
    subdomain_count = len(domain.split(".")) - 2
    has_many_subs = subdomain_count > 2
    checks.append({"label": "Normal Subdomains" if not has_many_subs else f"{subdomain_count} Subdomains", "ok": not has_many_subs})
    if has_many_subs:
        total_score += 10
        flags.append("EXCESSIVE_SUBDOMAINS")

    # ── 7. URL Length (10 pts) ──
    url_len = len(raw)
    is_long = url_len > 75
    checks.append({"label": f"Normal Length ({url_len})" if not is_long else f"Long URL ({url_len} chars)", "ok": not is_long})
    if is_long:
        total_score += min(10, int((url_len - 75) / 10) + 5)
        flags.append("LONG_URL")

    # ── 8. Excessive Dashes in Domain (8 pts) ──
    dash_count = domain.count("-")
    has_dashes = dash_count > 2
    checks.append({"label": "Clean Domain Format" if not has_dashes else f"{dash_count} Dashes in Domain", "ok": not has_dashes})
    if has_dashes:
        total_score += 8
        flags.append("EXCESSIVE_DASHES")

    # ── 9. Encoded Characters / Obfuscation (10 pts) ──
    has_encoded = "%" in raw or "@" in domain or "0x" in raw
    checks.append({"label": "No Obfuscation" if not has_encoded else "URL Obfuscation Found", "ok": not has_encoded})
    if has_encoded:
        total_score += 10
        flags.append("URL_OBFUSCATION")

    # ── 10. Suspicious File Extensions (8 pts) ──
    bad_exts = [".exe", ".zip", ".js", ".php", ".bat", ".cmd", ".scr"]
    has_bad_ext = any(path.endswith(ext) for ext in bad_exts)
    checks.append({"label": "Safe File Extension" if not has_bad_ext else "Suspicious File Type", "ok": not has_bad_ext})
    if has_bad_ext:
        total_score += 8
        flags.append("SUSPICIOUS_EXTENSION")

    # ── Cap & Verdict ──
    score = min(total_score, 100)
    if score < 20:
        verdict = "Safe"
    elif score < 45:
        verdict = "Suspicious"
    else:
        verdict = "Phishing"

    return {
        "score": score,
        "verdict": verdict,
        "flags": flags,
        "checks": checks,
        "domain": domain,
        "url_length": url_len
    }

# ─── Input Validation ─────────────────────────────────────────────────────────

def validate_url(url: str) -> tuple[bool, str]:
    if not url:
        return False, "URL is required."
    if len(url) > 2048:
        return False, "URL is too long (max 2048 characters)."
    # Must look like a URL
    if not re.match(r'^(https?://)?[^\s/$.?#].[^\s]*$', url, re.I):
        return False, "Invalid URL format."
    # Block localhost / private IPs
    if re.search(r'(localhost|127\.0\.0\.|192\.168\.|10\.\d|::1)', url, re.I):
        return False, "Private/local URLs are not allowed."
    return True, ""

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    score = 0
    error = None

    if request.method == "POST":
        ip = request.remote_addr or "unknown"

        # Rate limit check
        if is_rate_limited(ip):
            error = "Too many requests. Please wait a moment."
            return render_template("index.html", error=error), 429

        url = request.form.get("url", "").strip()

        # Validate
        valid, msg = validate_url(url)
        if not valid:
            error = msg
            return render_template("index.html", error=error), 400

        # Analyze
        analysis = analyze_url(url)
        score = analysis["score"]
        verdict = analysis["verdict"]
        checks = analysis["checks"]
        flags = analysis["flags"]

        # Log (no PII stored)
        try:
            log_scan(ip, url, analysis)
        except Exception:
            pass  # Never let logging crash the app

        result = {
            "verdict": verdict,
            "score": score,
            "checks": checks,
            "flags": flags,
            "domain": analysis.get("domain", ""),
        }

    return render_template("index.html", result=result, score=score, error=error)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    JSON API endpoint for programmatic access.
    POST /api/scan
    Body: {"url": "https://example.com"}
    Returns: JSON with full analysis
    """
    ip = request.remote_addr or "unknown"

    if is_rate_limited(ip):
        return jsonify({"error": "Rate limit exceeded. Try again in 60 seconds."}), 429

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Request body must be JSON with a 'url' field."}), 400

    url = str(data["url"]).strip()
    valid, msg = validate_url(url)
    if not valid:
        return jsonify({"error": msg}), 400

    analysis = analyze_url(url)

    try:
        log_scan(ip, url, analysis)
    except Exception:
        pass

    return jsonify({
        "url": url,
        "domain": analysis.get("domain"),
        "verdict": analysis["verdict"],
        "score": analysis["score"],
        "risk_level": (
            "low" if analysis["score"] < 20 else
            "medium" if analysis["score"] < 45 else
            "high"
        ),
        "flags": analysis["flags"],
        "checks": analysis["checks"],
        "scanned_at": datetime.utcnow().isoformat() + "Z"
    })


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return basic scan statistics from log file."""
    if not os.path.exists(LOG_FILE):
        return jsonify({"total_scans": 0, "verdicts": {}})

    verdicts = {"Safe": 0, "Suspicious": 0, "Phishing": 0}
    total = 0
    with open(LOG_FILE) as f:
        for line in f:
            try:
                entry = json.loads(line)
                v = entry.get("verdict")
                if v in verdicts:
                    verdicts[v] += 1
                total += 1
            except Exception:
                continue

    return jsonify({
        "total_scans": total,
        "verdicts": verdicts
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
