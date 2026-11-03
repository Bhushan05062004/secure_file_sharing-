"""Tamper-evident audit log: every row stores a SHA-256 hash chained to the
previous row, so editing or deleting a row breaks verification."""
import hashlib
from datetime import datetime, timezone

from flask import g, request

from db import get_db

GENESIS = "0" * 64


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash(prev, ts, uid, uname, action, target, ip, success, details):
    payload = "|".join(str(x) for x in
                       (prev, ts, uid, uname, action, target, ip, int(success), details))
    return hashlib.sha256(payload.encode()).hexdigest()


def log(action, success=True, target=None, details=None, username=None):
    db = get_db()
    user = getattr(g, "user", None)
    uid = user["id"] if user else None
    uname = user["username"] if user else username
    ip = request.remote_addr if request else None
    row = db.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["entry_hash"] if row else GENESIS
    ts = now_iso()
    h = _hash(prev, ts, uid, uname, action, target, ip, success, details)
    db.execute("INSERT INTO audit_logs (ts,user_id,username,action,target,ip,success,"
               "details,prev_hash,entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (ts, uid, uname, action, target, ip, int(success), details, prev, h))
    db.commit()


def verify_chain():
    """Returns (ok, first_bad_id)."""
    prev = GENESIS
    for r in get_db().execute("SELECT * FROM audit_logs ORDER BY id"):
        expected = _hash(prev, r["ts"], r["user_id"], r["username"], r["action"],
                         r["target"], r["ip"], r["success"], r["details"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return False, r["id"]
        prev = r["entry_hash"]
    return True, None
