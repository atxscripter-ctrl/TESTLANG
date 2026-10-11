"""
ATXxKEEM HUB — full stack.
Key system with HWID binding, pastebin, admin panel, telegram bot, stats, audit.
"""

import os
import io
import re
import json
import time
import hmac
import random
import string
import sqlite3
import secrets
import hashlib
import threading
import traceback
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict

import requests
from flask import (
    Flask, render_template, request, jsonify, session, g,
    redirect, abort, Response, send_from_directory, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


# ============================================================
# APP / CONFIG
# ============================================================
app = Flask(__name__)
app.secret_key = os.getenv("ATX_SECRET", secrets.token_hex(32))
app.permanent_session_lifetime = 60 * 60 * 24 * 30
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("ATX_HTTPS", "0") == "1",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

DATA_DIR = os.getenv("DATA_DIR", "/data")
KEYS_FILE         = os.path.join(DATA_DIR, "keys.json")
SCRIPTS_FILE      = os.path.join(DATA_DIR, "scripts.json")
PASTES_FILE       = os.path.join(DATA_DIR, "pastes.json")
CONFIG_FILE       = os.path.join(DATA_DIR, "config.json")
BLACKLIST_FILE    = os.path.join(DATA_DIR, "blacklist.json")
AUDIT_FILE        = os.path.join(DATA_DIR, "audit.json")
STATS_FILE        = os.path.join(DATA_DIR, "stats.json")
USERS_DB          = os.path.join(DATA_DIR, "users.db")

TELEGRAM_CHANNEL  = os.getenv("TG_CHANNEL", "https://t.me/+_eEH_XgASVFhNmNl")
TELEGRAM_PREMIUM  = os.getenv("TG_PREMIUM", "https://t.me/AntraxdevZ")
TELEGRAM_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip()
TELEGRAM_ADMIN_IDS = set(
    x.strip() for x in os.getenv("TG_ADMIN_IDS", "").split(",") if x.strip()
)
TELEGRAM_NOTIFY_CHAT = os.getenv("TG_NOTIFY_CHAT", "").strip()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK", "").strip()

DEFAULT_PAYLOAD_URL = os.getenv("SCRIPT_PAYLOAD_URL", "https://pastebin.com/raw/V4jrqcQz")

ADMIN_USERNAME = os.getenv("ATX_ADMIN_USER", "antrax")
ADMIN_PASSWORD = os.getenv("ATX_ADMIN_PASS", "antraxdevzagodz")

KEY_VALID_HOURS = 12
TASK_COOLDOWN_SECONDS = 30
PASTE_MAX_LENGTH = 100000
ORIGIN_ALLOWLIST = set(
    x.strip() for x in os.getenv("ATX_ORIGINS", "").split(",") if x.strip()
)

# HMAC signer for TTL tokens
signer = URLSafeTimedSerializer(app.secret_key, salt="atx-ttl")


# ============================================================
# STORAGE
# ============================================================
def ensure_storage():
    os.makedirs(DATA_DIR, exist_ok=True)
    for f, default in [
        (KEYS_FILE, {}),
        (SCRIPTS_FILE, {}),
        (PASTES_FILE, {}),
        (BLACKLIST_FILE, {"keys": [], "hwids": []}),
        (AUDIT_FILE, []),
        (STATS_FILE, {"daily": {}, "totals": {}}),
    ]:
        if not os.path.exists(f):
            with open(f, "w") as fp:
                json.dump(default, fp, indent=2)
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as fp:
            json.dump({
                "payloads": {
                    "free":    DEFAULT_PAYLOAD_URL,
                    "premium": DEFAULT_PAYLOAD_URL,
                    "vip":     DEFAULT_PAYLOAD_URL,
                },
                "key_durations_hours": {"free": 12, "premium": 24 * 7, "vip": 24 * 30},
            }, fp, indent=2)
    init_db()


def _load(path):
    ensure_storage()
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save(path, data):
    ensure_storage()
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_keys():       return _load(KEYS_FILE)
def save_keys(d):      _save(KEYS_FILE, d)
def load_scripts():    return _load(SCRIPTS_FILE)
def save_scripts(d):   _save(SCRIPTS_FILE, d)
def load_pastes():     return _load(PASTES_FILE)
def save_pastes(d):    _save(PASTES_FILE, d)
def load_blacklist():  return _load(BLACKLIST_FILE)
def save_blacklist(d): _save(BLACKLIST_FILE, d)
def load_audit():      return _load(AUDIT_FILE) or []
def save_audit(d):     _save(AUDIT_FILE, d[-5000:])  # cap
def load_stats():      return _load(STATS_FILE)
def save_stats(d):     _save(STATS_FILE, d)
def load_config():     return _load(CONFIG_FILE)
def save_config(d):    _save(CONFIG_FILE, d)


# ============================================================
# STATS
# ============================================================
def _today_key():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def stat_incr(name, amount=1):
    s = load_stats()
    day = _today_key()
    s.setdefault("daily", {}).setdefault(day, {})
    s["daily"][day][name] = s["daily"][day].get(name, 0) + amount
    s.setdefault("totals", {})
    s["totals"][name] = s["totals"].get(name, 0) + amount
    save_stats(s)


def stats_snapshot(days=14):
    s = load_stats()
    daily = s.get("daily", {})
    keys = sorted(daily.keys())[-days:]
    series = {
        "labels": keys,
        "keys_generated":  [daily[k].get("keys_generated", 0) for k in keys],
        "validations":     [daily[k].get("validations", 0) for k in keys],
        "pastes_created":  [daily[k].get("pastes_created", 0) for k in keys],
        "registrations":   [daily[k].get("registrations", 0) for k in keys],
        "paste_views":     [daily[k].get("paste_views", 0) for k in keys],
    }
    return {"totals": s.get("totals", {}), "series": series}


# ============================================================
# AUDIT LOG
# ============================================================
def audit(action, actor=None, detail=None, ip=None):
    log = load_audit()
    log.append({
        "ts": int(time.time()),
        "action": action,
        "actor": actor,
        "detail": detail or {},
        "ip": ip or request.remote_addr if request else None,
    })
    save_audit(log)


# ============================================================
# DB
# ============================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(USERS_DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(USERS_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created INTEGER NOT NULL,
            paste_count INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            api_token TEXT,
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            bonus_hours INTEGER NOT NULL DEFAULT 0
        )
    """)
    # idempotent migrations
    for ddl in [
        "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN api_token TEXT",
        "ALTER TABLE users ADD COLUMN referral_code TEXT",
        "ALTER TABLE users ADD COLUMN referred_by INTEGER",
        "ALTER TABLE users ADD COLUMN bonus_hours INTEGER NOT NULL DEFAULT 0",
    ]:
        try: conn.execute(ddl)
        except sqlite3.OperationalError: pass
    conn.commit()
    conn.close()
    seed_admin()


def seed_admin():
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    now = int(time.time())
    if row is None:
        conn.execute(
            "INSERT INTO users (username, password_hash, created, paste_count, is_admin, referral_code) VALUES (?, ?, ?, 0, 1, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now, gen_referral_code()),
        )
    else:
        conn.execute(
            "UPDATE users SET password_hash = ?, is_admin = 1, is_banned = 0 WHERE username = ?",
            (generate_password_hash(ADMIN_PASSWORD), ADMIN_USERNAME),
        )
        if not row["referral_code"]:
            conn.execute("UPDATE users SET referral_code = ? WHERE id = ?",
                         (gen_referral_code(), row["id"]))
    conn.commit()
    conn.close()


def find_user_by_username(u):
    return get_db().execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()


def find_user_by_id(uid):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def find_user_by_token(tok):
    return get_db().execute("SELECT * FROM users WHERE api_token = ?", (tok,)).fetchone()


def create_user(username, password, referred_by_code=None):
    db = get_db()
    ref_id = None
    if referred_by_code:
        r = db.execute("SELECT id FROM users WHERE referral_code = ?", (referred_by_code,)).fetchone()
        if r:
            ref_id = r["id"]
    code = gen_referral_code()
    while db.execute("SELECT 1 FROM users WHERE referral_code = ?", (code,)).fetchone():
        code = gen_referral_code()
    db.execute(
        "INSERT INTO users (username, password_hash, created, referral_code, referred_by) VALUES (?, ?, ?, ?, ?)",
        (username, generate_password_hash(password), int(time.time()), code, ref_id),
    )
    db.commit()
    if ref_id:
        db.execute("UPDATE users SET bonus_hours = bonus_hours + 2 WHERE id = ?", (ref_id,))
        db.commit()
    return find_user_by_username(username)


def bump_paste_count(uid):
    db = get_db()
    db.execute("UPDATE users SET paste_count = paste_count + 1 WHERE id = ?", (uid,))
    db.commit()


# ============================================================
# AUTH
# ============================================================
def current_user():
    uid = session.get("user_id")
    if not uid:
        # fallback to API token
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            u = find_user_by_token(auth[7:].strip())
            if u:
                return u
        return None
    return find_user_by_id(uid)


def login_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        u = current_user()
        if not u:
            return jsonify({"success": False, "error": "Login required"}), 401
        if u["is_banned"]:
            return jsonify({"success": False, "error": "Account banned"}), 403
        return fn(*a, **kw)
    return w


def admin_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        u = current_user()
        if not u:
            return jsonify({"success": False, "error": "Login required"}), 401
        if not u["is_admin"]:
            return jsonify({"success": False, "error": "Admin only"}), 403
        if u["is_banned"]:
            return jsonify({"success": False, "error": "Account banned"}), 403
        return fn(*a, **kw)
    return w


def valid_username(u):
    return 3 <= len(u) <= 20 and all(c.isalnum() or c == "_" for c in u)


COMMON_PASSWORDS = {
    "password","123456","12345678","qwerty","111111","abc123","password1",
    "letmein","welcome","admin","admin123","root","toor","pass123",
}


def password_ok(p):
    if len(p) < 8: return False, "Password must be at least 8 characters"
    if p.lower() in COMMON_PASSWORDS: return False, "Password too common"
    return True, ""


def user_public(u):
    if not u:
        return None
    return {
        "id": u["id"],
        "username": u["username"],
        "created": u["created"],
        "paste_count": u["paste_count"],
        "is_admin": bool(u["is_admin"]),
        "is_banned": bool(u["is_banned"]),
        "referral_code": u["referral_code"] if "referral_code" in u.keys() else None,
        "bonus_hours": u["bonus_hours"] if "bonus_hours" in u.keys() else 0,
    }


# ============================================================
# IDS
# ============================================================
def gen_key(tier="free"):
    return f"ATX-{tier[:3].upper()}-" + "-".join(secrets.token_hex(2).upper() for _ in range(3))


def gen_script_id():
    return "SC-" + secrets.token_hex(4).upper()


def gen_paste_id(length=8):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def gen_referral_code():
    return "REF" + secrets.token_hex(3).upper()


def gen_api_token():
    return "atx_" + secrets.token_urlsafe(32)


# ============================================================
# CAPTCHA
# ============================================================
def gen_math_challenge():
    op_sym = random.choice(["+", "-", "x"])
    if op_sym == "x":
        a, b = random.randint(2, 12), random.randint(2, 12)
        ans = a * b
    else:
        a = random.randint(10, 50); b = random.randint(5, 30)
        if op_sym == "-" and b > a: a, b = b, a
        ans = a + b if op_sym == "+" else a - b
    return {"question": f"What is {a} {op_sym} {b}?", "answer": str(ans)}


def gen_text_challenge():
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "".join(random.choices(chars, k=5))
    return {"question": f"Type this code: {code}", "answer": code}


def gen_sequence_challenge():
    start = random.randint(1, 5); step = random.randint(2, 4)
    seq = [start + step * i for i in range(4)]
    return {"question": f"What comes next? {', '.join(map(str, seq))}, ?",
            "answer": str(start + step * 4)}


def gen_challenge():
    return random.choice([gen_math_challenge, gen_text_challenge, gen_sequence_challenge])()


# ============================================================
# RATE LIMITING
# ============================================================
_rate_store = defaultdict(list)
_rate_lock = threading.Lock()


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def rate_limit(name, limit, window):
    """limit requests per window seconds, keyed by (name, IP)."""
    def deco(fn):
        @wraps(fn)
        def w(*a, **kw):
            key = (name, _client_ip())
            now = time.time()
            with _rate_lock:
                bucket = _rate_store[key]
                bucket[:] = [t for t in bucket if now - t < window]
                if len(bucket) >= limit:
                    retry = int(window - (now - bucket[0])) + 1
                    resp = jsonify({"success": False, "error": f"Rate limited. Retry in {retry}s"})
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
                bucket.append(now)
            return fn(*a, **kw)
        return w
    return deco


def _rate_cleanup():
    while True:
        time.sleep(120)
        now = time.time()
        with _rate_lock:
            for k in list(_rate_store.keys()):
                _rate_store[k][:] = [t for t in _rate_store[k] if now - t < 600]
                if not _rate_store[k]:
                    del _rate_store[k]


threading.Thread(target=_rate_cleanup, daemon=True).start()


# ============================================================
# CSRF + ORIGIN
# ============================================================
def _origin_ok():
    origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
    if not origin:
        return True  # allow same-origin / curl / scripts that don't send origin
    if not ORIGIN_ALLOWLIST:
        return True  # permissive if not configured
    for o in ORIGIN_ALLOWLIST:
        if origin.startswith(o):
            return True
    return False


@app.before_request
def _csrf_and_origin():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # skip for API-token-authenticated requests
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return None
        if not _origin_ok():
            return jsonify({"success": False, "error": "Origin not allowed"}), 403
        # CSRF: only enforced on cookie-auth'd state-changing calls
        if session.get("user_id"):
            token = request.headers.get("X-CSRF-Token") or (request.get_json(silent=True) or {}).get("_csrf")
            expected = session.get("csrf_token")
            if expected and token != expected:
                return jsonify({"success": False, "error": "CSRF token invalid"}), 403
    return None


def _ensure_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    return session["csrf_token"]


# ============================================================
# PAYLOADS / SCRIPT
# ============================================================
def get_payload_url(tier="free"):
    cfg = load_config()
    payloads = cfg.get("payloads") or {}
    url = (payloads.get(tier) or "").strip()
    if not url:
        url = (payloads.get("free") or "").strip() or DEFAULT_PAYLOAD_URL
    return url


def get_key_duration(tier="free"):
    cfg = load_config()
    durs = cfg.get("key_durations_hours") or {}
    return int(durs.get(tier, KEY_VALID_HOURS))


def build_script_payload(tier="free", ttl_seconds=86400, hwid_required=False):
    """Returns a loadstring. Uses a signed token URL for short TTL."""
    url = get_payload_url(tier)
    # Non-signed: direct URL. Signed: /t/<token>
    token = signer.dumps({"tier": tier, "u": url, "hwid_required": hwid_required})
    base = request.host_url.rstrip("/") if request else ""
    short = f"{base}/t/{token}"
    if hwid_required:
        return (
            'local hwid = game:GetService("RbxAnalyticsService"):GetClientId()\n'
            f'loadstring(game:HttpGet("{short}?hwid=" .. hwid))()'
        )
    return f'loadstring(game:HttpGet("{short}"))()'


# ============================================================
# KEY LOGIC
# ============================================================
def key_is_blacklisted(key):
    bl = load_blacklist()
    return key in (bl.get("keys") or [])


def hwid_is_blacklisted(hwid):
    if not hwid:
        return False
    bl = load_blacklist()
    return hwid in (bl.get("hwids") or [])


def validate_key_entry(key, hwid=None):
    """
    Returns (ok, info, error)
    info: {"tier", "expires", "hwid"}
    """
    if key_is_blacklisted(key):
        return False, None, "Key blacklisted"
    if hwid_is_blacklisted(hwid):
        return False, None, "HWID blacklisted"
    keys = load_keys()
    entry = keys.get(key)
    if not entry:
        return False, None, "Invalid key"
    if entry.get("expires", 0) < time.time():
        return False, None, "Key expired"
    bound = entry.get("hwid")
    if bound and hwid and bound != hwid:
        return False, None, "HWID mismatch"
    if not bound and hwid:
        entry["hwid"] = hwid
        entry["hwid_bound_at"] = int(time.time())
        keys[key] = entry
        save_keys(keys)
    return True, entry, None


# ============================================================
# PASTE HELPERS
# ============================================================
def paste_is_expired(p):
    exp = p.get("expires")
    if not exp:
        return False
    return exp < time.time()


def _purge_expired_pastes():
    while True:
        try:
            pastes = load_pastes()
            now = time.time()
            changed = False
            for pid in list(pastes.keys()):
                if pastes[pid].get("expires") and pastes[pid]["expires"] < now:
                    del pastes[pid]
                    changed = True
            if changed:
                save_pastes(pastes)
        except Exception:
            traceback.print_exc()
        time.sleep(600)


threading.Thread(target=_purge_expired_pastes, daemon=True).start()


# ============================================================
# TELEGRAM BOT (long-polling)
# ============================================================
_tg_offset = 0


def tg_api(method, payload=None):
    if not TELEGRAM_BOT_TOKEN:
        return None
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}",
            json=payload or {}, timeout=35,
        )
        return r.json()
    except Exception:
        return None


def tg_notify(text):
    if TELEGRAM_NOTIFY_CHAT:
        tg_api("sendMessage", {"chat_id": TELEGRAM_NOTIFY_CHAT, "text": text, "parse_mode": "HTML"})


def _tg_handle(update):
    msg = update.get("message") or update.get("edited_message")
    if not msg: return
    chat_id = msg.get("chat", {}).get("id")
    from_id = str(msg.get("from", {}).get("id", ""))
    text = (msg.get("text") or "").strip()
    if not text.startswith("/"):
        return

    # Only admins can control
    if TELEGRAM_ADMIN_IDS and from_id not in TELEGRAM_ADMIN_IDS:
        tg_api("sendMessage", {"chat_id": chat_id, "text": "Not authorized."})
        return

    parts = text.split()
    cmd = parts[0].lower()

    if cmd == "/start":
        tg_api("sendMessage", {"chat_id": chat_id,
            "text": "ATX bot online.\nCommands:\n/seturl <tier> <url>\n/urls\n/genkey <tier>\n/stats"})
    elif cmd == "/seturl" and len(parts) >= 3:
        tier, url = parts[1].lower(), parts[2]
        if tier not in ("free", "premium", "vip"):
            tg_api("sendMessage", {"chat_id": chat_id, "text": "tier must be free/premium/vip"})
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            tg_api("sendMessage", {"chat_id": chat_id, "text": "url must be http(s)"})
            return
        cfg = load_config()
        cfg.setdefault("payloads", {})[tier] = url
        save_config(cfg)
        audit("tg.seturl", actor=f"tg:{from_id}", detail={"tier": tier, "url": url})
        tg_api("sendMessage", {"chat_id": chat_id, "text": f"[{tier}] -> {url}"})
    elif cmd == "/urls":
        cfg = load_config()
        lines = [f"{k}: {v}" for k, v in (cfg.get("payloads") or {}).items()]
        tg_api("sendMessage", {"chat_id": chat_id, "text": "\n".join(lines) or "none"})
    elif cmd == "/genkey" and len(parts) >= 2:
        tier = parts[1].lower()
        if tier not in ("free", "premium", "vip"):
            tg_api("sendMessage", {"chat_id": chat_id, "text": "tier must be free/premium/vip"})
            return
        keys = load_keys()
        k = gen_key(tier)
        now = int(time.time())
        keys[k] = {"created": now, "expires": now + get_key_duration(tier) * 3600, "tier": tier}
        save_keys(keys)
        stat_incr("keys_generated")
        audit("tg.genkey", actor=f"tg:{from_id}", detail={"tier": tier, "key": k})
        tg_api("sendMessage", {"chat_id": chat_id, "text": f"{k} ({tier})"})
    elif cmd == "/stats":
        snap = stats_snapshot()
        t = snap["totals"]
        txt = "\n".join(f"{k}: {v}" for k, v in t.items()) or "no data"
        tg_api("sendMessage", {"chat_id": chat_id, "text": txt})


def _tg_poll():
    global _tg_offset
    if not TELEGRAM_BOT_TOKEN:
        return
    print("[tg] bot polling started")
    while True:
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates",
                params={"offset": _tg_offset + 1, "timeout": 30},
                timeout=40,
            )
            data = r.json()
            for u in data.get("result", []):
                _tg_offset = max(_tg_offset, u["update_id"])
                try:
                    _tg_handle(u)
                except Exception:
                    traceback.print_exc()
        except Exception:
            time.sleep(5)


def start_tg_thread():
    if TELEGRAM_BOT_TOKEN:
        threading.Thread(target=_tg_poll, daemon=True).start()


# ============================================================
# DISCORD WEBHOOK
# ============================================================
def discord_notify(content):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": content[:1900]}, timeout=10)
    except Exception:
        pass


# ============================================================
# ROUTES — ROOT
# ============================================================
@app.route("/")
def index():
    csrf = _ensure_csrf()
    return render_template(
        "index.html",
        telegram_channel=TELEGRAM_CHANNEL,
        telegram_premium=TELEGRAM_PREMIUM,
        csrf_token=csrf,
    )


@app.route("/status")
def status():
    keys = load_keys()
    now = time.time()
    active = sum(1 for v in keys.values() if v.get("expires", 0) > now)
    pastes = load_pastes()
    return jsonify({
        "status": "ok",
        "time": int(now),
        "active_keys": active,
        "total_keys": len(keys),
        "total_pastes": len(pastes),
        "uptime_hint": "always on",
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": int(time.time())})


# ============================================================
# ROUTES — AUTH
# ============================================================
@app.route("/api/auth/register", methods=["POST"])
@rate_limit("register", 5, 600)
def auth_register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    ref = (data.get("ref") or "").strip() or None

    if not valid_username(username):
        return jsonify({"success": False, "error": "Username 3-20 chars, alnum/underscore"}), 400
    ok, msg = password_ok(password)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400
    if find_user_by_username(username):
        return jsonify({"success": False, "error": "Username taken"}), 409

    u = create_user(username, password, ref)
    session.permanent = True
    session["user_id"] = u["id"]
    _ensure_csrf()
    stat_incr("registrations")
    audit("auth.register", actor=username)
    return jsonify({"success": True, "user": user_public(u), "csrf_token": session["csrf_token"]})


@app.route("/api/auth/login", methods=["POST"])
@rate_limit("login", 8, 300)
def auth_login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    u = find_user_by_username(username)
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
    if u["is_banned"]:
        return jsonify({"success": False, "error": "Account banned"}), 403

    session.permanent = True
    session["user_id"] = u["id"]
    _ensure_csrf()
    return jsonify({"success": True, "user": user_public(u), "csrf_token": session["csrf_token"]})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.pop("user_id", None)
    return jsonify({"success": True})


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    u = current_user()
    return jsonify({"success": True, "user": user_public(u), "csrf_token": _ensure_csrf()})


@app.route("/api/auth/apitoken", methods=["POST"])
@login_required
def auth_apitoken():
    u = current_user()
    if not u["api_token"]:
        db = get_db()
        tok = gen_api_token()
        db.execute("UPDATE users SET api_token = ? WHERE id = ?", (tok, u["id"]))
        db.commit()
        audit("user.apitoken.create", actor=u["username"])
    u = find_user_by_id(u["id"])
    return jsonify({"success": True, "api_token": u["api_token"]})


@app.route("/api/auth/apitoken/revoke", methods=["POST"])
@login_required
def auth_apitoken_revoke():
    u = current_user()
    db = get_db()
    db.execute("UPDATE users SET api_token = NULL WHERE id = ?", (u["id"],))
    db.commit()
    audit("user.apitoken.revoke", actor=u["username"])
    return jsonify({"success": True})


# ============================================================
# ROUTES — CAPTCHA
# ============================================================
@app.route("/api/get-challenge", methods=["POST"])
@rate_limit("challenge", 20, 60)
def get_challenge():
    c = gen_challenge()
    session["captcha_answer"] = c["answer"].upper()
    session["captcha_time"] = time.time()
    session["captcha_solved"] = False
    return jsonify({"success": True, "question": c["question"]})


@app.route("/api/verify-human", methods=["POST"])
@rate_limit("verify", 30, 60)
def verify_human():
    data = request.get_json() or {}
    answer = (data.get("answer") or "").strip().upper()
    expected = session.get("captcha_answer", "")
    ts = session.get("captcha_time", 0)
    if not expected:
        return jsonify({"success": False, "error": "No challenge"}), 400
    if time.time() - ts > 300:
        return jsonify({"success": False, "error": "Expired"}), 410
    if answer != expected:
        session.pop("captcha_answer", None)
        return jsonify({"success": False, "error": "Wrong answer"}), 400
    session["captcha_solved"] = True
    session["captcha_solved_time"] = time.time()
    session.pop("captcha_answer", None)
    return jsonify({"success": True})


# ============================================================
# ROUTES — KEY
# ============================================================
@app.route("/api/generate-key", methods=["POST"])
@rate_limit("genkey", 5, 3600)
def generate_key():
    if not session.get("captcha_solved"):
        return jsonify({"success": False, "error": "Complete verification first"}), 403
    elapsed = time.time() - session.get("captcha_solved_time", 0)
    if elapsed < TASK_COOLDOWN_SECONDS:
        return jsonify({"success": False, "error": f"Wait {int(TASK_COOLDOWN_SECONDS - elapsed)}s"}), 429

    tier = "free"
    keys = load_keys()
    new_key = gen_key(tier)
    now = int(time.time())
    dur_h = get_key_duration(tier)
    keys[new_key] = {"created": now, "expires": now + dur_h * 3600, "tier": tier}
    save_keys(keys)

    session.pop("captcha_solved", None)
    session.pop("captcha_solved_time", None)
    stat_incr("keys_generated")
    return jsonify({"success": True, "key": new_key, "expires_in_hours": dur_h, "tier": tier})


@app.route("/api/validate-key", methods=["GET", "POST"])
@rate_limit("validate", 120, 60)
def validate_key():
    if request.method == "GET":
        key = (request.args.get("key") or "").strip()
        hwid = (request.args.get("hwid") or "").strip() or None
    else:
        d = request.get_json(silent=True) or {}
        key = (d.get("key") or "").strip()
        hwid = (d.get("hwid") or "").strip() or None
    if not key:
        return jsonify({"valid": False, "error": "No key"}), 400

    ok, entry, err = validate_key_entry(key, hwid)
    stat_incr("validations")
    if not ok:
        return jsonify({"valid": False, "error": err}), 403

    # touch last_used
    keys = load_keys()
    if key in keys:
        keys[key]["last_used"] = int(time.time())
        save_keys(keys)

    return jsonify({
        "valid": True,
        "tier": entry.get("tier", "free"),
        "expires": entry.get("expires"),
        "hwid": entry.get("hwid"),
    })


# ============================================================
# ROUTES — SCRIPT
# ============================================================
@app.route("/api/generate-script", methods=["POST"])
@rate_limit("genscript", 10, 3600)
def generate_script():
    if not session.get("captcha_solved"):
        return jsonify({"success": False, "error": "Complete verification first"}), 403
    elapsed = time.time() - session.get("captcha_solved_time", 0)
    if elapsed < TASK_COOLDOWN_SECONDS:
        return jsonify({"success": False, "error": f"Wait {int(TASK_COOLDOWN_SECONDS - elapsed)}s"}), 429

    scripts = load_scripts()
    sid = gen_script_id()
    scripts[sid] = {"created": int(time.time())}
    save_scripts(scripts)

    payload = build_script_payload("free", ttl_seconds=86400, hwid_required=False)
    session.pop("captcha_solved", None)
    session.pop("captcha_solved_time", None)
    stat_incr("scripts_delivered")
    return jsonify({"success": True, "script_id": sid, "payload": payload})


# ============================================================
# ROUTES — TTL LOADER
# ============================================================
@app.route("/t/<token>", methods=["GET"])
def ttl_loader(token):
    try:
        data = signer.loads(token, max_age=60 * 60 * 24 * 7)
    except SignatureExpired:
        return "Token expired", 410
    except BadSignature:
        return "Invalid token", 400

    url = data.get("u")
    if not url:
        return "Bad token", 400
    try:
        r = requests.get(url, timeout=10)
        return Response(r.text, mimetype="text/plain")
    except Exception:
        return "Upstream error", 502


# ============================================================
# ROUTES — SHORT LOADER
# ============================================================
@app.route("/r/<pid>", methods=["GET"])
def short_loader(pid):
    pastes = load_pastes()
    entry = pastes.get(pid)
    if not entry or paste_is_expired(entry):
        return "Not found", 404
    # HWID check on loadstring-side paste delivery
    hwid = request.args.get("hwid")
    if hwid and hwid_is_blacklisted(hwid):
        return "-- blocked", 403
    return Response(entry.get("content", ""), mimetype="text/plain")


# ============================================================
# ROUTES — ADMIN
# ============================================================
@app.route("/api/admin/payloads", methods=["GET"])
@admin_required
def admin_get_payloads():
    cfg = load_config()
    return jsonify({
        "success": True,
        "payloads": cfg.get("payloads", {}),
        "durations": cfg.get("key_durations_hours", {}),
    })


@app.route("/api/admin/payloads", methods=["POST"])
@admin_required
def admin_set_payloads():
    data = request.get_json() or {}
    tier = (data.get("tier") or "").lower()
    url = (data.get("url") or "").strip()
    if tier not in ("free", "premium", "vip"):
        return jsonify({"success": False, "error": "tier must be free/premium/vip"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"success": False, "error": "URL must be http(s)"}), 400
    cfg = load_config()
    cfg.setdefault("payloads", {})[tier] = url
    save_config(cfg)
    audit("admin.payload.set", actor=current_user()["username"], detail={"tier": tier, "url": url})
    return jsonify({"success": True, "payloads": cfg["payloads"]})


@app.route("/api/admin/durations", methods=["POST"])
@admin_required
def admin_set_durations():
    data = request.get_json() or {}
    tier = (data.get("tier") or "").lower()
    hours = int(data.get("hours", 0))
    if tier not in ("free", "premium", "vip"):
        return jsonify({"success": False, "error": "invalid tier"}), 400
    if hours < 1 or hours > 24 * 365:
        return jsonify({"success": False, "error": "hours must be 1..8760"}), 400
    cfg = load_config()
    cfg.setdefault("key_durations_hours", {})[tier] = hours
    save_config(cfg)
    audit("admin.duration.set", actor=current_user()["username"], detail={"tier": tier, "hours": hours})
    return jsonify({"success": True, "durations": cfg["key_durations_hours"]})


# ---- admin: keys
@app.route("/api/admin/keys", methods=["GET"])
@admin_required
def admin_list_keys():
    keys = load_keys()
    now = time.time()
    items = []
    for k, v in keys.items():
        items.append({
            "key": k,
            "tier": v.get("tier", "free"),
            "created": v.get("created"),
            "expires": v.get("expires"),
            "hwid": v.get("hwid"),
            "last_used": v.get("last_used"),
            "active": v.get("expires", 0) > now,
            "blacklisted": key_is_blacklisted(k),
        })
    items.sort(key=lambda x: x.get("created", 0), reverse=True)
    return jsonify({"success": True, "keys": items})


@app.route("/api/admin/keys/revoke", methods=["POST"])
@admin_required
def admin_revoke_key():
    data = request.get_json() or {}
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"success": False, "error": "key required"}), 400
    keys = load_keys()
    if key in keys:
        del keys[key]
        save_keys(keys)
    bl = load_blacklist()
    bl.setdefault("keys", [])
    if key not in bl["keys"]:
        bl["keys"].append(key)
    save_blacklist(bl)
    audit("admin.key.revoke", actor=current_user()["username"], detail={"key": key})
    return jsonify({"success": True})


@app.route("/api/admin/keys/gen", methods=["POST"])
@admin_required
def admin_gen_key():
    data = request.get_json() or {}
    tier = (data.get("tier") or "free").lower()
    if tier not in ("free", "premium", "vip"):
        return jsonify({"success": False, "error": "invalid tier"}), 400
    keys = load_keys()
    k = gen_key(tier)
    now = int(time.time())
    keys[k] = {"created": now, "expires": now + get_key_duration(tier) * 3600, "tier": tier}
    save_keys(keys)
    stat_incr("keys_generated")
    audit("admin.key.gen", actor=current_user()["username"], detail={"tier": tier, "key": k})
    return jsonify({"success": True, "key": k, "tier": tier})


# ---- admin: blacklist
@app.route("/api/admin/blacklist", methods=["GET"])
@admin_required
def admin_list_blacklist():
    return jsonify({"success": True, **load_blacklist()})


@app.route("/api/admin/blacklist/add", methods=["POST"])
@admin_required
def admin_bl_add():
    data = request.get_json() or {}
    kind = (data.get("kind") or "").strip()
    value = (data.get("value") or "").strip()
    if kind not in ("keys", "hwids") or not value:
        return jsonify({"success": False, "error": "kind keys|hwids + value required"}), 400
    bl = load_blacklist()
    bl.setdefault(kind, [])
    if value not in bl[kind]:
        bl[kind].append(value)
    save_blacklist(bl)
    audit("admin.blacklist.add", actor=current_user()["username"], detail={"kind": kind, "value": value})
    return jsonify({"success": True})


@app.route("/api/admin/blacklist/remove", methods=["POST"])
@admin_required
def admin_bl_remove():
    data = request.get_json() or {}
    kind = (data.get("kind") or "").strip()
    value = (data.get("value") or "").strip()
    bl = load_blacklist()
    if kind in bl and value in bl[kind]:
        bl[kind].remove(value)
        save_blacklist(bl)
    audit("admin.blacklist.remove", actor=current_user()["username"], detail={"kind": kind, "value": value})
    return jsonify({"success": True})


# ---- admin: users
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    db = get_db()
    rows = db.execute("SELECT * FROM users ORDER BY created DESC LIMIT 500").fetchall()
    return jsonify({"success": True, "users": [
        {
            "id": r["id"],
            "username": r["username"],
            "created": r["created"],
            "paste_count": r["paste_count"],
            "is_admin": bool(r["is_admin"]),
            "is_banned": bool(r["is_banned"]),
            "bonus_hours": r["bonus_hours"] if "bonus_hours" in r.keys() else 0,
        } for r in rows
    ]})


@app.route("/api/admin/users/<int:uid>/ban", methods=["POST"])
@admin_required
def admin_ban_user(uid):
    db = get_db()
    db.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (uid,))
    db.commit()
    audit("admin.user.ban", actor=current_user()["username"], detail={"uid": uid})
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:uid>/unban", methods=["POST"])
@admin_required
def admin_unban_user(uid):
    db = get_db()
    db.execute("UPDATE users SET is_banned = 0 WHERE id = ?", (uid,))
    db.commit()
    audit("admin.user.unban", actor=current_user()["username"], detail={"uid": uid})
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:uid>/promote", methods=["POST"])
@admin_required
def admin_promote(uid):
    db = get_db()
    db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (uid,))
    db.commit()
    audit("admin.user.promote", actor=current_user()["username"], detail={"uid": uid})
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:uid>/demote", methods=["POST"])
@admin_required
def admin_demote(uid):
    actor = current_user()
    if uid == actor["id"]:
        return jsonify({"success": False, "error": "Cannot demote yourself"}), 400
    db = get_db()
    db.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (uid,))
    db.commit()
    audit("admin.user.demote", actor=actor["username"], detail={"uid": uid})
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid):
    actor = current_user()
    if uid == actor["id"]:
        return jsonify({"success": False, "error": "Cannot delete yourself"}), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    audit("admin.user.delete", actor=actor["username"], detail={"uid": uid})
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:uid>/reset_password", methods=["POST"])
@admin_required
def admin_reset_pw(uid):
    data = request.get_json() or {}
    new_pw = (data.get("password") or "").strip()
    ok, msg = password_ok(new_pw)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(new_pw), uid))
    db.commit()
    audit("admin.user.resetpw", actor=current_user()["username"], detail={"uid": uid})
    return jsonify({"success": True})


# ---- admin: stats & audit
@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    return jsonify({"success": True, **stats_snapshot()})


@app.route("/api/admin/audit", methods=["GET"])
@admin_required
def admin_audit():
    log = load_audit()
    log = list(reversed(log))[:300]
    return jsonify({"success": True, "entries": log})


# ============================================================
# ROUTES — PASTEBIN
# ============================================================
@app.route("/api/paste/create", methods=["POST"])
@login_required
@rate_limit("paste_create", 20, 3600)
def paste_create():
    data = request.get_json() or {}
    content = (data.get("content") or "").strip()
    title = (data.get("title") or "").strip()[:120]
    syntax = (data.get("syntax") or "text").strip()[:24]
    expiry = (data.get("expiry") or "never").strip()
    password = (data.get("password") or "").strip()

    if not content:
        return jsonify({"success": False, "error": "Content required"}), 400
    if len(content) > PASTE_MAX_LENGTH:
        return jsonify({"success": False, "error": f"Max {PASTE_MAX_LENGTH}"}), 413

    expires_at = None
    map_secs = {"1h": 3600, "1d": 86400, "7d": 86400 * 7, "30d": 86400 * 30}
    if expiry in map_secs:
        expires_at = int(time.time()) + map_secs[expiry]

    pastes = load_pastes()
    pid = gen_paste_id()
    while pid in pastes:
        pid = gen_paste_id()

    entry = {
        "title": title,
        "content": content,
        "syntax": syntax,
        "created": int(time.time()),
        "views": 0,
        "unique_views": [],
        "user_id": session["user_id"],
        "username": current_user()["username"],
        "ip": request.remote_addr,
        "expires": expires_at,
    }
    if password:
        entry["password_hash"] = generate_password_hash(password)
    pastes[pid] = entry
    save_pastes(pastes)
    bump_paste_count(session["user_id"])
    stat_incr("pastes_created")
    audit("paste.create", actor=current_user()["username"], detail={"id": pid})
    discord_notify(f"New paste by **{entry['username']}**: {title or '(untitled)'} — /paste/{pid}")

    return jsonify({
        "success": True,
        "id": pid,
        "url": f"/paste/{pid}",
        "raw_url": f"/raw/{pid}",
        "short_url": f"/r/{pid}",
    })


@app.route("/api/paste/mine", methods=["GET"])
@login_required
def paste_mine():
    uid = session["user_id"]
    pastes = load_pastes()
    mine = []
    for pid, v in pastes.items():
        if v.get("user_id") != uid: continue
        if paste_is_expired(v): continue
        mine.append({
            "id": pid,
            "title": v.get("title", ""),
            "syntax": v.get("syntax", "text"),
            "created": v.get("created"),
            "views": v.get("views", 0),
            "expires": v.get("expires"),
            "has_password": bool(v.get("password_hash")),
        })
    mine.sort(key=lambda x: x.get("created", 0), reverse=True)
    return jsonify({"success": True, "pastes": mine})


@app.route("/api/paste/recent", methods=["GET"])
def paste_recent():
    pastes = load_pastes()
    live = []
    for pid, v in pastes.items():
        if paste_is_expired(v): continue
        live.append({
            "id": pid,
            "title": v.get("title", ""),
            "username": v.get("username", "anon"),
            "created": v.get("created"),
            "views": v.get("views", 0),
            "has_password": bool(v.get("password_hash")),
        })
    live.sort(key=lambda x: x.get("created", 0), reverse=True)
    return jsonify({"success": True, "pastes": live[:50]})


@app.route("/api/paste/search", methods=["GET"])
def paste_search():
    q = (request.args.get("q") or "").strip().lower()
    if not q:
        return jsonify({"success": True, "pastes": []})
    pastes = load_pastes()
    hits = []
    for pid, v in pastes.items():
        if paste_is_expired(v): continue
        if q in (v.get("title", "").lower()) or q in (v.get("content", "").lower()):
            hits.append({
                "id": pid,
                "title": v.get("title", ""),
                "username": v.get("username", "anon"),
                "created": v.get("created"),
                "views": v.get("views", 0),
            })
    hits.sort(key=lambda x: x.get("created", 0), reverse=True)
    return jsonify({"success": True, "pastes": hits[:50]})


@app.route("/api/paste/get/<pid>", methods=["GET"])
def paste_get(pid):
    pastes = load_pastes()
    entry = pastes.get(pid)
    if not entry or paste_is_expired(entry):
        return jsonify({"success": False, "error": "Not found"}), 404

    # password gate
    if entry.get("password_hash"):
        pw = request.args.get("pw") or ""
        if not pw or not check_password_hash(entry["password_hash"], pw):
            return jsonify({"success": False, "error": "Password required", "locked": True}), 401

    entry["views"] = entry.get("views", 0) + 1
    ip = _client_ip()
    uniq = entry.setdefault("unique_views", [])
    if ip not in uniq:
        uniq.append(ip)
        if len(uniq) > 5000: uniq.pop(0)
    pastes[pid] = entry
    save_pastes(pastes)
    stat_incr("paste_views")

    return jsonify({
        "success": True,
        "id": pid,
        "title": entry.get("title", ""),
        "content": entry.get("content", ""),
        "syntax": entry.get("syntax", "text"),
        "created": entry.get("created"),
        "updated": entry.get("updated"),
        "views": entry["views"],
        "unique_views": len(uniq),
        "username": entry.get("username", "anon"),
        "expires": entry.get("expires"),
        "has_password": bool(entry.get("password_hash")),
        "raw_url": f"/raw/{pid}",
    })


@app.route("/api/paste/edit/<pid>", methods=["POST"])
@login_required
def paste_edit(pid):
    uid = session["user_id"]
    u = find_user_by_id(uid)
    pastes = load_pastes()
    entry = pastes.get(pid)
    if not entry or paste_is_expired(entry):
        return jsonify({"success": False, "error": "Not found"}), 404
    if entry.get("user_id") != uid and not u["is_admin"]:
        return jsonify({"success": False, "error": "Not yours"}), 403

    data = request.get_json() or {}
    if "title" in data:
        entry["title"] = (data["title"] or "").strip()[:120]
    if "content" in data:
        c = (data["content"] or "").strip()
        if not c:
            return jsonify({"success": False, "error": "Content empty"}), 400
        if len(c) > PASTE_MAX_LENGTH:
            return jsonify({"success": False, "error": "Too long"}), 413
        entry["content"] = c
    if "syntax" in data:
        entry["syntax"] = (data["syntax"] or "text").strip()[:24]
    if "password" in data:
        pw = (data["password"] or "").strip()
        if pw:
            entry["password_hash"] = generate_password_hash(pw)
        else:
            entry.pop("password_hash", None)
    entry["updated"] = int(time.time())
    pastes[pid] = entry
    save_pastes(pastes)
    audit("paste.edit", actor=u["username"], detail={"id": pid})
    return jsonify({"success": True})


@app.route("/api/paste/delete/<pid>", methods=["POST", "DELETE"])
@login_required
def paste_delete(pid):
    uid = session["user_id"]
    u = find_user_by_id(uid)
    pastes = load_pastes()
    entry = pastes.get(pid)
    if not entry:
        return jsonify({"success": False, "error": "Not found"}), 404
    if entry.get("user_id") != uid and not u["is_admin"]:
        return jsonify({"success": False, "error": "Not yours"}), 403
    del pastes[pid]
    save_pastes(pastes)
    audit("paste.delete", actor=u["username"], detail={"id": pid})
    return jsonify({"success": True})


@app.route("/api/paste/fork/<pid>", methods=["POST"])
@login_required
def paste_fork(pid):
    pastes = load_pastes()
    src = pastes.get(pid)
    if not src or paste_is_expired(src):
        return jsonify({"success": False, "error": "Not found"}), 404
    if src.get("password_hash"):
        return jsonify({"success": False, "error": "Cannot fork password-protected paste"}), 403

    new_id = gen_paste_id()
    while new_id in pastes:
        new_id = gen_paste_id()
    u = current_user()
    pastes[new_id] = {
        "title": (src.get("title", "") + " (fork)")[:120],
        "content": src.get("content", ""),
        "syntax": src.get("syntax", "text"),
        "created": int(time.time()),
        "views": 0,
        "unique_views": [],
        "user_id": u["id"],
        "username": u["username"],
        "ip": request.remote_addr,
        "expires": None,
        "forked_from": pid,
    }
    save_pastes(pastes)
    bump_paste_count(u["id"])
    stat_incr("pastes_created")
    audit("paste.fork", actor=u["username"], detail={"from": pid, "to": new_id})
    return jsonify({"success": True, "id": new_id, "url": f"/paste/{new_id}", "raw_url": f"/raw/{new_id}"})


# ============================================================
# ROUTES — RAW / PASTE VIEW
# ============================================================
def _content_type_for(syntax):
    return {
        "lua": "text/x-lua; charset=utf-8",
        "javascript": "application/javascript; charset=utf-8",
        "python": "text/x-python; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "css": "text/css; charset=utf-8",
        "json": "application/json; charset=utf-8",
        "cpp": "text/x-c++src; charset=utf-8",
        "csharp": "text/x-csharp; charset=utf-8",
        "bash": "text/x-shellscript; charset=utf-8",
    }.get(syntax, "text/plain; charset=utf-8")


@app.route("/api/paste/raw/<pid>", methods=["GET"])
@app.route("/raw/<pid>", methods=["GET"])
def paste_raw(pid):
    pastes = load_pastes()
    entry = pastes.get(pid)
    if not entry or paste_is_expired(entry):
        return "Not found", 404
    if entry.get("password_hash"):
        pw = request.args.get("pw") or ""
        if not pw or not check_password_hash(entry["password_hash"], pw):
            return "Password required", 401
    return Response(
        entry.get("content", ""),
        mimetype=_content_type_for(entry.get("syntax", "text")).split(";")[0],
        content_type=_content_type_for(entry.get("syntax", "text")),
    )


@app.route("/paste/<pid>")
def paste_view(pid):
    csrf = _ensure_csrf()
    return render_template(
        "index.html",
        telegram_channel=TELEGRAM_CHANNEL,
        telegram_premium=TELEGRAM_PREMIUM,
        csrf_token=csrf,
        paste_id=pid,
    )


# ============================================================
# BOOT
# ============================================================
ensure_storage()

if __name__ == "__main__":
    start_tg_thread()
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port, threaded=True)