"""Tamper-evident audit log: every row stores an HMAC-SHA256 chained to the
previous row with an external secret key, preventing chain manipulation or local tampering."""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone

from flask import current_app, g, request

from db import get_db

GENESIS = "0" * 64


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_audit_key() -> bytes:
    """Retrieves HMAC key from config or external instance/audit.key file."""
    if current_app.config.get("AUDIT_HMAC_KEY"):
        val = current_app.config["AUDIT_HMAC_KEY"]
        return val.encode() if isinstance(val, str) else val

    key_file = os.path.join(current_app.instance_path, "audit.key")
    if not os.path.exists(key_file):
        os.makedirs(current_app.instance_path, exist_ok=True)
        key_bytes = secrets.token_bytes(32)
        with open(key_file, "wb") as fh:
            fh.write(key_bytes)
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return key_bytes

    with open(key_file, "rb") as fh:
        return fh.read()


def content_hmac(data: bytes) -> str:
    """HMAC-SHA256 for file content deduplication and integrity check without leaking plaintext SHA-256."""
    return hmac.new(get_audit_key(), data, hashlib.sha256).hexdigest()


def _hash(prev, ts, uid, uname, action, target, ip, success, details, key: bytes):
    payload = "|".join(str(x) for x in
                       (prev, ts, uid, uname, action, target, ip, int(success), details))
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def log(action, success=True, target=None, details=None, username=None):
    """Inserts a tamper-evident audit record within a BEGIN IMMEDIATE transaction to prevent chain forks."""
    db = get_db()
    key = get_audit_key()
    user = getattr(g, "user", None)
    uid = user["id"] if user else None
    uname = user["username"] if user else username
    ip = request.remote_addr if request else None
    ts = now_iso()

    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["entry_hash"] if row else GENESIS
        h = _hash(prev, ts, uid, uname, action, target, ip, success, details, key)
        db.execute("INSERT INTO audit_logs (ts,user_id,username,action,target,ip,success,"
                   "details,prev_hash,entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (ts, uid, uname, action, target, ip, int(success), details, prev, h))
        db.execute("COMMIT")
    except Exception:
        try:
            db.execute("ROLLBACK")
        except Exception:
            pass
        raise


def verify_chain():
    """Verifies HMAC hash chain from genesis. Returns (ok, first_bad_id)."""
    key = get_audit_key()
    prev = GENESIS
    for r in get_db().execute("SELECT * FROM audit_logs ORDER BY id"):
        expected = _hash(prev, r["ts"], r["user_id"], r["username"], r["action"],
                         r["target"], r["ip"], r["success"], r["details"], key)
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return False, r["id"]
        prev = r["entry_hash"]
    return True, None
