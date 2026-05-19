"""
PDF Squeeze — Licence Server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ed25519-signed JWT licences. SQLite backend. Flask + flask-limiter.

Endpoints:
  POST /activate          — first run on a new machine
  POST /validate          — periodic soft re-check (client calls this)
  POST /admin/issue       — create a new licence key
  POST /admin/revoke      — revoke a key (refunds, chargebacks)
  POST /admin/deactivate  — remove one machine binding (transfers)
  GET  /admin/key/<key>   — inspect a key's activations
  GET  /health            — uptime probe

Environment variables (all required unless marked optional):
  PRIVATE_KEY_B64   — base64-encoded Ed25519 private key (32 raw bytes)
  ADMIN_KEY         — secret header value for /admin/* routes
  DATABASE_URL      — SQLite path, e.g. "sqlite:////data/licences.db"
                      or "sqlite:///licences.db" for relative path
  FLASK_ENV         — "production" (optional, defaults safe)
  LOG_LEVEL         — "INFO" | "WARNING" | "ERROR" (optional, default INFO)
"""

import os
import json
import time
import base64
import logging
import sqlite3
import functools
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO")),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("licence_server")

# ── App + rate limiter ────────────────────────────────────────────────────────

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # no global default; set per-route
    storage_uri="memory://",    # fine for a single-dyno deployment
    strategy="fixed-window",
)

# ── Key loading ───────────────────────────────────────────────────────────────

def _load_private_key() -> Ed25519PrivateKey:
    raw_b64 = os.environ.get("PRIVATE_KEY_B64", "")
    if not raw_b64:
        raise RuntimeError(
            "PRIVATE_KEY_B64 environment variable is not set. "
            "Generate a keypair with: python keygen.py"
        )
    try:
        raw = base64.b64decode(raw_b64)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise RuntimeError(f"Failed to load private key: {exc}") from exc


PRIVATE_KEY: Ed25519PrivateKey = _load_private_key()
PUBLIC_KEY:  Ed25519PublicKey  = PRIVATE_KEY.public_key()

TOKEN_TTL_SECONDS = 365 * 86_400   # 1 year


# ── Database ──────────────────────────────────────────────────────────────────

def _db_path() -> str:
    """
    Resolve the database file path from DATABASE_URL.
    Accepts:
      sqlite:////absolute/path/licences.db   (absolute, 4 slashes)
      sqlite:///relative/licences.db         (relative to cwd, 3 slashes)
    Falls back to ./licences.db if not set.
    """
    url = os.environ.get("DATABASE_URL", "sqlite:///licences.db")
    if url.startswith("sqlite:////"):
        return url[len("sqlite:///"):]      # absolute path
    elif url.startswith("sqlite:///"):
        return url[len("sqlite:///"):]      # relative path
    else:
        raise RuntimeError(f"Unsupported DATABASE_URL scheme: {url!r}. Use sqlite://.")


DB_PATH = _db_path()


def get_db() -> sqlite3.Connection:
    """Return a per-request DB connection (stored in Flask's g)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc: Optional[Exception]) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS licences (
            key         TEXT    PRIMARY KEY,
            issued_to   TEXT    NOT NULL DEFAULT '',
            seats       INTEGER NOT NULL DEFAULT 1,
            created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activations (
            key            TEXT    NOT NULL,
            machine_id     TEXT    NOT NULL,
            activated_at   INTEGER NOT NULL,
            last_seen_at   INTEGER NOT NULL,
            activation_ip  TEXT    NOT NULL DEFAULT '',
            PRIMARY KEY (key, machine_id),
            FOREIGN KEY  (key) REFERENCES licences(key)
        );

        CREATE TABLE IF NOT EXISTS revoked (
            key         TEXT    PRIMARY KEY,
            reason      TEXT    NOT NULL DEFAULT '',
            revoked_at  INTEGER NOT NULL,
            FOREIGN KEY (key) REFERENCES licences(key)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          INTEGER NOT NULL,
            event       TEXT    NOT NULL,
            key         TEXT    NOT NULL DEFAULT '',
            machine_id  TEXT    NOT NULL DEFAULT '',
            ip          TEXT    NOT NULL DEFAULT '',
            detail      TEXT    NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_audit_key ON audit_log(key);
        CREATE INDEX IF NOT EXISTS idx_audit_ts  ON audit_log(ts);
    """)
    conn.commit()
    conn.close()
    logger.info("Database ready at %s", DB_PATH)


# ── Audit helper ──────────────────────────────────────────────────────────────

def audit(event: str, key: str = "", machine_id: str = "",
          detail: str = "") -> None:
    ip = request.remote_addr or ""
    # Also forward-for header if behind a proxy (Railway sets this)
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (ts,event,key,machine_id,ip,detail) "
            "VALUES (?,?,?,?,?,?)",
            (int(time.time()), event, key, machine_id, ip, detail)
        )
        db.commit()
    except Exception as exc:
        logger.error("Audit write failed: %s", exc)
    logger.info("AUDIT %s key=%r machine=%r ip=%r detail=%r",
                event, key, machine_id, ip, detail)


# ── JWT helpers ───────────────────────────────────────────────────────────────

_HEADER_B64 = (
    base64.urlsafe_b64encode(
        json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def make_token(key: str, machine_id: str) -> str:
    now     = int(time.time())
    payload = _b64url(json.dumps({
        "key":        key,
        "machine_id": machine_id,
        "iat":        now,
        "exp":        now + TOKEN_TTL_SECONDS,
    }).encode())
    signing_input = f"{_HEADER_B64}.{payload}".encode()
    sig = _b64url(PRIVATE_KEY.sign(signing_input))
    return f"{_HEADER_B64}.{payload}.{sig}"


def verify_token(token_str: str) -> Tuple[bool, dict]:
    """Verify Ed25519 signature and return (valid, payload)."""
    try:
        parts = token_str.split(".")
        if len(parts) != 3:
            return False, {}
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature     = _b64url_decode(sig_b64)
        PUBLIC_KEY.verify(signature, signing_input)
        payload = json.loads(_b64url_decode(payload_b64))
        return True, payload
    except InvalidSignature:
        return False, {}
    except Exception as exc:
        logger.debug("Token verify error: %s", exc)
        return False, {}


# ── Admin auth decorator ──────────────────────────────────────────────────────

def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        admin_key = os.environ.get("ADMIN_KEY", "")
        if not admin_key:
            logger.error("ADMIN_KEY env var is not set — admin routes are locked")
            return jsonify({"detail": "Admin not configured"}), 500
        if request.headers.get("X-Admin-Key", "") != admin_key:
            audit("ADMIN_AUTH_FAIL")
            return jsonify({"detail": "Forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ── Input validation helpers ──────────────────────────────────────────────────

def _clean_key(raw: str) -> str:
    return raw.strip().upper()


def _valid_machine_id(mid: str) -> bool:
    """machine_id is a 32-char hex string produced by the client."""
    return isinstance(mid, str) and len(mid) == 32 and all(
        c in "0123456789abcdef" for c in mid.lower()
    )


# ═════════════════════════════════════════════════════════════════════════════
# Public endpoints
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/activate", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")
def activate():
    """
    Called on first launch on a new machine.
    Body: { "key": "PHIL-0525-XXXX", "machine_id": "<32-hex>" }
    Returns: { "token": "<jwt>" }
    """
    data       = request.get_json(silent=True) or {}
    key        = _clean_key(data.get("key", ""))
    machine_id = data.get("machine_id", "")

    if not key or not machine_id:
        return jsonify({"detail": "Missing key or machine_id"}), 400

    if not _valid_machine_id(machine_id):
        return jsonify({"detail": "Invalid machine_id format"}), 400

    db = get_db()

    # ── Does key exist? ────────────────────────────────────────────────────
    row = db.execute(
        "SELECT seats FROM licences WHERE key=?", (key,)
    ).fetchone()
    if not row:
        audit("ACTIVATE_BAD_KEY", key=key, machine_id=machine_id)
        return jsonify({"detail": "Invalid licence key"}), 404

    # ── Revoked? ───────────────────────────────────────────────────────────
    if db.execute("SELECT 1 FROM revoked WHERE key=?", (key,)).fetchone():
        audit("ACTIVATE_REVOKED", key=key, machine_id=machine_id)
        return jsonify({"detail": "This licence has been revoked. Contact support."}), 410

    seats    = row["seats"]
    machines = [
        r["machine_id"]
        for r in db.execute(
            "SELECT machine_id FROM activations WHERE key=?", (key,)
        ).fetchall()
    ]

    now = int(time.time())

    if machine_id in machines:
        # Re-activation on same machine — update last_seen and reissue token
        db.execute(
            "UPDATE activations SET last_seen_at=? WHERE key=? AND machine_id=?",
            (now, key, machine_id)
        )
        db.commit()
        audit("ACTIVATE_REISSUE", key=key, machine_id=machine_id)
    elif len(machines) >= seats:
        audit("ACTIVATE_SEAT_FULL", key=key, machine_id=machine_id,
              detail=f"seats={seats} used={len(machines)}")
        return jsonify({
            "detail": (
                f"This licence is already activated on {seats} machine(s). "
                "Contact support to transfer it to this machine."
            )
        }), 409
    else:
        ip = (request.headers.get("X-Forwarded-For", "") or
              request.remote_addr or "")
        db.execute(
            "INSERT INTO activations (key, machine_id, activated_at, last_seen_at, activation_ip) "
            "VALUES (?,?,?,?,?)",
            (key, machine_id, now, now, ip.split(",")[0].strip())
        )
        db.commit()
        audit("ACTIVATE_OK", key=key, machine_id=machine_id)

    return jsonify({"token": make_token(key, machine_id)}), 200


@app.route("/validate", methods=["POST"])
@limiter.limit("60 per minute")
def validate():
    """
    Weekly soft re-check called by the client.
    Body: { "token": "<jwt>", "machine_id": "<32-hex>" }
    Returns 200 if still valid, 4xx otherwise.
    """
    data       = request.get_json(silent=True) or {}
    token_str  = data.get("token", "")
    machine_id = data.get("machine_id", "")

    if not token_str or not machine_id:
        return jsonify({"detail": "Missing token or machine_id"}), 400

    # ── Verify signature ───────────────────────────────────────────────────
    valid, payload = verify_token(token_str)
    if not valid:
        audit("VALIDATE_BAD_SIG", machine_id=machine_id)
        return jsonify({"detail": "Invalid token signature"}), 401

    key              = payload.get("key", "")
    token_machine_id = payload.get("machine_id", "")

    # ── Machine binding ────────────────────────────────────────────────────
    if token_machine_id != machine_id:
        audit("VALIDATE_MACHINE_MISMATCH", key=key, machine_id=machine_id)
        return jsonify({"detail": "Token machine mismatch"}), 401

    db = get_db()

    # ── Key still exists? ──────────────────────────────────────────────────
    if not db.execute("SELECT 1 FROM licences WHERE key=?", (key,)).fetchone():
        audit("VALIDATE_KEY_GONE", key=key, machine_id=machine_id)
        return jsonify({"detail": "Licence no longer exists"}), 404

    # ── Revoked? ───────────────────────────────────────────────────────────
    if db.execute("SELECT 1 FROM revoked WHERE key=?", (key,)).fetchone():
        audit("VALIDATE_REVOKED", key=key, machine_id=machine_id)
        return jsonify({"detail": "Licence revoked"}), 410

    # ── Still an active activation on this machine? ────────────────────────
    if not db.execute(
        "SELECT 1 FROM activations WHERE key=? AND machine_id=?",
        (key, machine_id)
    ).fetchone():
        audit("VALIDATE_NOT_ACTIVATED", key=key, machine_id=machine_id)
        return jsonify({"detail": "Not activated on this machine"}), 404

    # ── Update last_seen ───────────────────────────────────────────────────
    db.execute(
        "UPDATE activations SET last_seen_at=? WHERE key=? AND machine_id=?",
        (int(time.time()), key, machine_id)
    )
    db.commit()
    audit("VALIDATE_OK", key=key, machine_id=machine_id)
    return jsonify({"ok": True}), 200


# ═════════════════════════════════════════════════════════════════════════════
# Admin endpoints  (X-Admin-Key header required)
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/admin/issue", methods=["POST"])
@require_admin
@limiter.limit("30 per hour")
def admin_issue():
    """
    Create a new licence key.
    Body: { "key": "PHIL-0525-XXXX", "issued_to": "Name", "seats": 1 }
    """
    data      = request.get_json(silent=True) or {}
    key       = _clean_key(data.get("key", ""))
    issued_to = data.get("issued_to", "").strip()
    seats     = int(data.get("seats", 1))

    if not key:
        return jsonify({"detail": "Missing key"}), 400
    if seats < 1 or seats > 10:
        return jsonify({"detail": "seats must be 1–10"}), 400

    db = get_db()
    existing = db.execute("SELECT 1 FROM licences WHERE key=?", (key,)).fetchone()
    if existing:
        return jsonify({"detail": "Key already exists"}), 409

    db.execute(
        "INSERT INTO licences (key, issued_to, seats, created_at) VALUES (?,?,?,?)",
        (key, issued_to, seats, int(time.time()))
    )
    db.commit()
    audit("ADMIN_ISSUE", key=key, detail=f"issued_to={issued_to!r} seats={seats}")
    return jsonify({"ok": True, "key": key, "issued_to": issued_to, "seats": seats}), 201


@app.route("/admin/revoke", methods=["POST"])
@require_admin
def admin_revoke():
    """
    Revoke a licence key (refund, chargeback, abuse).
    Body: { "key": "...", "reason": "refund" }
    Revoked keys cannot activate or validate. Existing tokens will be rejected
    on next weekly revalidation.
    """
    data   = request.get_json(silent=True) or {}
    key    = _clean_key(data.get("key", ""))
    reason = data.get("reason", "").strip()

    if not key:
        return jsonify({"detail": "Missing key"}), 400

    db = get_db()
    if not db.execute("SELECT 1 FROM licences WHERE key=?", (key,)).fetchone():
        return jsonify({"detail": "Key not found"}), 404

    db.execute(
        "INSERT OR REPLACE INTO revoked (key, reason, revoked_at) VALUES (?,?,?)",
        (key, reason, int(time.time()))
    )
    db.commit()
    audit("ADMIN_REVOKE", key=key, detail=f"reason={reason!r}")
    return jsonify({"ok": True}), 200


@app.route("/admin/unrevoke", methods=["POST"])
@require_admin
def admin_unrevoke():
    """Undo a revocation (e.g. chargeback resolved)."""
    data = request.get_json(silent=True) or {}
    key  = _clean_key(data.get("key", ""))
    if not key:
        return jsonify({"detail": "Missing key"}), 400
    db = get_db()
    db.execute("DELETE FROM revoked WHERE key=?", (key,))
    db.commit()
    audit("ADMIN_UNREVOKE", key=key)
    return jsonify({"ok": True}), 200


@app.route("/admin/deactivate", methods=["POST"])
@require_admin
def admin_deactivate():
    """
    Remove one machine binding so the user can activate on a new machine.
    Body: { "key": "...", "machine_id": "..." }
    Pass machine_id="*" to deactivate ALL machines (full reset).
    """
    data       = request.get_json(silent=True) or {}
    key        = _clean_key(data.get("key", ""))
    machine_id = data.get("machine_id", "")

    if not key or not machine_id:
        return jsonify({"detail": "Missing key or machine_id"}), 400

    db = get_db()
    if not db.execute("SELECT 1 FROM licences WHERE key=?", (key,)).fetchone():
        return jsonify({"detail": "Key not found"}), 404

    if machine_id == "*":
        db.execute("DELETE FROM activations WHERE key=?", (key,))
        audit("ADMIN_DEACTIVATE_ALL", key=key)
    else:
        db.execute(
            "DELETE FROM activations WHERE key=? AND machine_id=?",
            (key, machine_id)
        )
        audit("ADMIN_DEACTIVATE", key=key, machine_id=machine_id)

    db.commit()
    return jsonify({"ok": True}), 200


@app.route("/admin/key/<path:key>", methods=["GET"])
@require_admin
def admin_inspect(key: str):
    """Return full details for a key: metadata, activations, revocation status."""
    key = _clean_key(key)
    db  = get_db()

    row = db.execute(
        "SELECT key, issued_to, seats, created_at FROM licences WHERE key=?", (key,)
    ).fetchone()
    if not row:
        return jsonify({"detail": "Key not found"}), 404

    activations = db.execute(
        "SELECT machine_id, activated_at, last_seen_at, activation_ip "
        "FROM activations WHERE key=?", (key,)
    ).fetchall()

    revoked = db.execute(
        "SELECT reason, revoked_at FROM revoked WHERE key=?", (key,)
    ).fetchone()

    recent_audit = db.execute(
        "SELECT ts, event, machine_id, ip, detail FROM audit_log "
        "WHERE key=? ORDER BY ts DESC LIMIT 20", (key,)
    ).fetchall()

    def _fmt(ts: int) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    return jsonify({
        "key":        row["key"],
        "issued_to":  row["issued_to"],
        "seats":      row["seats"],
        "created_at": _fmt(row["created_at"]),
        "revoked":    dict(revoked) if revoked else None,
        "activations": [
            {
                "machine_id":    a["machine_id"],
                "activated_at":  _fmt(a["activated_at"]),
                "last_seen_at":  _fmt(a["last_seen_at"]),
                "activation_ip": a["activation_ip"],
            }
            for a in activations
        ],
        "recent_audit": [
            {
                "ts":         _fmt(r["ts"]),
                "event":      r["event"],
                "machine_id": r["machine_id"],
                "ip":         r["ip"],
                "detail":     r["detail"],
            }
            for r in recent_audit
        ],
    }), 200


# ═════════════════════════════════════════════════════════════════════════════
# Health
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    """Used by Railway health checks and uptime monitors."""
    try:
        get_db().execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False
    status = 200 if db_ok else 503
    return jsonify({"ok": db_ok, "ts": int(time.time())}), status


# ═════════════════════════════════════════════════════════════════════════════
# Error handlers
# ═════════════════════════════════════════════════════════════════════════════

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"detail": "Too many requests. Try again later."}), 429


@app.errorhandler(404)
def not_found(e):
    return jsonify({"detail": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"detail": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Unhandled exception")
    return jsonify({"detail": "Internal server error"}), 500


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════
with app.app_context():
    init_db()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    # Never run with debug=True in production
    app.run(host="0.0.0.0", port=port, debug=False)