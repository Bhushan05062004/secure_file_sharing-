import re
import secrets
from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

import crypto_utils as cu
from audit import now_iso
from db import get_db

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_password(password, confirm):
    errs = []
    if len(password or "") < 10 or not re.search(r"[a-z]", password or "") \
            or not re.search(r"[A-Z]", password or "") or not re.search(r"\d", password or ""):
        errs.append("Password needs 10+ characters with upper-case, lower-case and a digit.")
    if password != confirm:
        errs.append("Passwords do not match.")
    return errs


def validate_registration(username, email, password, confirm):
    errs = []
    if not USERNAME_RE.match(username or ""):
        errs.append("Username must be 3-32 characters: letters, digits, underscore.")
    if not EMAIL_RE.match(email or "") or len(email or "") > 120:
        errs.append("Enter a valid email address.")
    errs.extend(validate_password(password, confirm))
    return errs


def create_user(username, email, password, role, rsa_bits, scrypt_n=None):
    """Creates the account together with its RSA key pair and session nonce."""
    if scrypt_n is None:
        scrypt_n = current_app.config.get("SCRYPT_N", cu.DEFAULT_SCRYPT_N) if current_app else cu.DEFAULT_SCRYPT_N

    priv, pub_pem = cu.generate_rsa_keypair(rsa_bits)
    enc_priv = cu.protect_private_key(priv, password, n=scrypt_n)
    session_nonce = secrets.token_hex(16)
    db = get_db()
    db.execute(
        "INSERT INTO users (username,email,password_hash,role,public_key,"
        "enc_private_key,session_nonce,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (username, email.lower(), generate_password_hash(password), role,
         pub_pem, enc_priv, session_nonce, now_iso())
    )


def change_password(user, old_password, new_password, scrypt_n=None):
    """Verifies old password, re-wraps private key with new password, updates hash and session nonce."""
    if not check_password_hash(user["password_hash"], old_password):
        return False, "Current password is incorrect.", None

    if scrypt_n is None:
        scrypt_n = current_app.config.get("SCRYPT_N", cu.DEFAULT_SCRYPT_N) if current_app else cu.DEFAULT_SCRYPT_N

    try:
        priv = cu.unlock_private_key(user["enc_private_key"], old_password)
    except ValueError:
        return False, "Unable to unlock private key with current password.", None

    new_enc_priv = cu.protect_private_key(priv, new_password, n=scrypt_n)
    new_nonce = secrets.token_hex(16)
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash=?, enc_private_key=?, session_nonce=? WHERE id=?",
        (generate_password_hash(new_password), new_enc_priv, new_nonce, user["id"])
    )
    return True, None, (priv, new_nonce)


def cleanup_expired_shares(db):
    """Revokes expired shares and deletes their corresponding RSA-wrapped keys so expired shares cannot be unwrapped."""
    now = now_iso()
    # Find active shares that have expired or reached download limits
    expired = db.execute(
        "SELECT id, file_id, recipient_id FROM shares WHERE revoked=0 "
        "AND ((expires_at IS NOT NULL AND expires_at <= ?) "
        "OR (max_downloads IS NOT NULL AND downloads >= max_downloads))",
        (now,)
    ).fetchall()

    for s in expired:
        db.execute("UPDATE shares SET revoked=1 WHERE id=?", (s["id"],))
        db.execute("DELETE FROM file_keys WHERE file_id=? AND user_id=?", (s["file_id"], s["recipient_id"]))
