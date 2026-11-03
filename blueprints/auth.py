import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import audit
import crypto_utils as cu
import db as database
import services

auth_bp = Blueprint("auth", __name__)

_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")

# Thread-safe in-memory sliding-window IP rate limiter
_IP_FAILURES = {}
_IP_LOCK = threading.Lock()


def is_ip_rate_limited(ip: str) -> bool:
    max_reqs = current_app.config.get("IP_RATE_LIMIT_MAX", 15)
    window = current_app.config.get("IP_RATE_LIMIT_WINDOW", 900)
    now = time.time()
    with _IP_LOCK:
        history = [t for t in _IP_FAILURES.get(ip, []) if t > now - window]
        _IP_FAILURES[ip] = history
        return len(history) >= max_reqs


def record_ip_failure(ip: str):
    now = time.time()
    with _IP_LOCK:
        history = [t for t in _IP_FAILURES.get(ip, []) if t > now - 900]
        history.append(now)
        _IP_FAILURES[ip] = history


def reset_ip_failures(ip: str):
    with _IP_LOCK:
        _IP_FAILURES.pop(ip, None)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        e = request.form.get("email", "").strip()
        p = request.form.get("password", "")
        errs = services.validate_registration(u, e, p, request.form.get("confirm", ""))
        if not errs:
            try:
                services.create_user(u, e, p, "user", current_app.config["RSA_BITS"])
            except sqlite3.IntegrityError:
                errs.append("Username or email is already registered.")
        if errs:
            for m in errs:
                flash(m, "danger")
            audit.log("REGISTER", False, username=u)
            return render_template("register.html"), 400
        audit.log("REGISTER", True, username=u)
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = database.get_db()
        ip = request.remote_addr or "unknown"

        # Per-IP rate limiting
        if is_ip_rate_limited(ip):
            audit.log("LOGIN_IP_RATE_LIMITED", False, details=f"IP {ip} rate limited")
            flash("Too many failed attempts from your IP. Please try again later.", "danger")
            return render_template("login.html"), 429

        uname = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        user = db.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
        now = audit.now_iso()

        # Check if account is locked
        is_locked = bool(user and user["locked_until"] and user["locked_until"] > now)

        if not user or is_locked:
            check_password_hash(_DUMMY_HASH, pw)  # equalize timing
            if is_locked:
                audit.log("LOGIN_LOCKED", False, username=uname)
            else:
                audit.log("LOGIN_FAIL_USER_UNKNOWN", False, username=uname)
            record_ip_failure(ip)
            # Generic error to prevent account existence or lock state disclosure
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        # Check password
        if check_password_hash(user["password_hash"], pw):
            try:
                priv = cu.unlock_private_key(user["enc_private_key"], pw)
            except ValueError:
                abort(400, "Key unlock failed.")

            # Generate fresh session nonce and reset failed attempts
            nonce = secrets.token_hex(16)
            db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, session_nonce=? WHERE id=?",
                       (nonce, user["id"]))

            session.clear()
            session.permanent = True
            session["uid"] = user["id"]
            session["nonce"] = nonce
            sid = secrets.token_hex(16)
            session["sid"] = sid

            # Put unlocked private key in keystore
            current_app.keystore_put(sid, priv)
            g.user = user
            reset_ip_failures(ip)
            audit.log("LOGIN", True)
            return redirect(url_for("files.dashboard"))

        # Password failed: atomically increment counter and calculate lockout in SQL
        record_ip_failure(ip)
        lock_until = (datetime.now(timezone.utc) + timedelta(
            minutes=current_app.config["LOCKOUT_MINUTES"])).isoformat(timespec="seconds")
        max_fails = current_app.config["MAX_FAILED_LOGINS"]

        db.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1, "
            "locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END "
            "WHERE id = ?",
            (max_fails, lock_until, user["id"])
        )

        audit.log("LOGIN", False, username=uname)
        flash("Invalid username or password.", "danger")
        return render_template("login.html"), 401

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    if g.user:
        # Invalidate server-side session nonce so replayed cookies cannot be used
        db = database.get_db()
        db.execute("UPDATE users SET session_nonce=? WHERE id=?", (secrets.token_hex(16), g.user["id"]))
        audit.log("LOGOUT", True)

    current_app.keystore_drop(session.get("sid"))
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
def change_password_view():
    if g.user is None:
        flash("Please log in.", "warning")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        errs = services.validate_password(new_pw, confirm_pw)
        if errs:
            for m in errs:
                flash(m, "danger")
            return render_template("change_password.html"), 400

        ok, err_msg, result = services.change_password(g.user, old_pw, new_pw)
        if not ok:
            audit.log("PASSWORD_CHANGE", False, details=err_msg)
            flash(err_msg, "danger")
            return render_template("change_password.html"), 400

        priv, new_nonce = result
        # Rotate session nonce and update keystore
        session["nonce"] = new_nonce
        sid = session.get("sid")
        if sid:
            current_app.keystore_put(sid, priv)

        audit.log("PASSWORD_CHANGE", True)
        flash("Password updated successfully and RSA private key re-encrypted.", "success")
        return redirect(url_for("files.dashboard"))

    return render_template("change_password.html")

