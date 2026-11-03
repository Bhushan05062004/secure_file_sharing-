import re
from werkzeug.security import generate_password_hash

import crypto_utils as cu
from audit import now_iso
from db import get_db

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username, email, password, confirm):
    errs = []
    if not USERNAME_RE.match(username or ""):
        errs.append("Username must be 3-32 characters: letters, digits, underscore.")
    if not EMAIL_RE.match(email or "") or len(email) > 120:
        errs.append("Enter a valid email address.")
    if len(password or "") < 10 or not re.search(r"[a-z]", password) \
            or not re.search(r"[A-Z]", password) or not re.search(r"\d", password):
        errs.append("Password needs 10+ characters with upper-case, lower-case and a digit.")
    if password != confirm:
        errs.append("Passwords do not match.")
    return errs


def create_user(username, email, password, role, rsa_bits):
    """Creates the account together with its RSA key pair. The private key is
    stored only in encrypted form (password-derived key)."""
    priv, pub_pem = cu.generate_rsa_keypair(rsa_bits)
    db = get_db()
    db.execute("INSERT INTO users (username,email,password_hash,role,public_key,"
               "enc_private_key,created_at) VALUES (?,?,?,?,?,?,?)",
               (username, email.lower(), generate_password_hash(password), role,
                pub_pem, cu.protect_private_key(priv, password), now_iso()))
    db.commit()
