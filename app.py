import functools
import hashlib
import io
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import audit
import crypto_utils as cu
import db as database
import services
from config import Config

# In-memory store of unlocked RSA private keys, keyed by session id.
# Never written to disk; cleared on logout / expiry / server restart.
_KEYSTORE, _KS_LOCK, _KEY_TTL = {}, threading.Lock(), 30 * 60
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def _ks_put(sid, key):
    with _KS_LOCK:
        cutoff = time.time() - _KEY_TTL
        for k in [k for k, v in _KEYSTORE.items() if v[1] < cutoff]:
            del _KEYSTORE[k]
        _KEYSTORE[sid] = (key, time.time())


def _ks_get(sid):
    with _KS_LOCK:
        item = _KEYSTORE.get(sid)
        if not item or item[1] < time.time() - _KEY_TTL:
            _KEYSTORE.pop(sid, None)
            return None
        _KEYSTORE[sid] = (item[0], time.time())
        return item[0]


def _ks_drop(sid):
    with _KS_LOCK:
        _KEYSTORE.pop(sid, None)


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config["DATABASE"] = os.path.join(app.instance_path, "securefs.db")
    app.config["STORAGE_DIR"] = os.path.join(app.instance_path, "storage")
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)

    key_file = os.path.join(app.instance_path, "secret.key")
    if not app.config.get("SECRET_KEY"):
        if not os.path.exists(key_file):
            with open(key_file, "w") as fh:
                fh.write(secrets.token_hex(32))
            os.chmod(key_file, 0o600)
        app.config["SECRET_KEY"] = open(key_file).read().strip()

    app.teardown_appcontext(database.close_db)
    with app.app_context():
        database.init_db()

    # ------------------------------------------------------------ helpers
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    def login_required(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if g.user is None:
                flash("Please log in.", "warning")
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapper

    def admin_required(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if g.user is None or g.user["role"] != "admin":
                audit.log("ADMIN_ACCESS_DENIED", False, target=request.path)
                abort(403)
            return view(*a, **kw)
        return wrapper

    def share_status(s):
        now = audit.now_iso()
        if s["revoked"]:
            return "revoked"
        if s["expires_at"] and s["expires_at"] <= now:
            return "expired"
        if s["max_downloads"] is not None and s["downloads"] >= s["max_downloads"]:
            return "exhausted"
        return "active"

    app.jinja_env.globals["share_status"] = share_status

    def fmt_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    app.jinja_env.filters["size"] = fmt_size

    def file_path(stored_name):
        return os.path.join(app.config["STORAGE_DIR"], stored_name)

    # ------------------------------------------------- request hooks
    @app.before_request
    def load_user_and_csrf():
        g.user = None
        uid = session.get("uid")
        if uid:
            g.user = database.get_db().execute(
                "SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if g.user is None:
                session.clear()
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "Invalid or missing CSRF token.")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "frame-ancestors 'none'")
        return resp

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def http_error(e):
        msg = {413: "File too large (limit 16 MB)."}.get(e.code, e.description)
        return render_template("error.html", code=e.code, message=msg), e.code

    # ------------------------------------------------------------ auth
    @app.route("/")
    def index():
        return redirect(url_for("dashboard") if g.user else url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            u = request.form.get("username", "").strip()
            e = request.form.get("email", "").strip()
            p = request.form.get("password", "")
            errs = services.validate_registration(u, e, p, request.form.get("confirm", ""))
            if not errs:
                try:
                    services.create_user(u, e, p, "user", app.config["RSA_BITS"])
                except sqlite3.IntegrityError:
                    errs.append("Username or email is already registered.")
            if errs:
                for m in errs:
                    flash(m, "danger")
                audit.log("REGISTER", False, username=u)
                return render_template("register.html"), 400
            audit.log("REGISTER", True, username=u)
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            db = database.get_db()
            uname = request.form.get("username", "").strip()
            pw = request.form.get("password", "")
            user = db.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
            now = audit.now_iso()
            if user and user["locked_until"] and user["locked_until"] > now:
                audit.log("LOGIN_LOCKED", False, username=uname)
                flash("Account temporarily locked. Try again later.", "danger")
                return render_template("login.html"), 429
            if not user:
                check_password_hash(_DUMMY_HASH, pw)  # equalise timing
            if user and check_password_hash(user["password_hash"], pw):
                db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
                           (user["id"],))
                db.commit()
                try:
                    priv = cu.unlock_private_key(user["enc_private_key"], pw)
                except ValueError:
                    abort(400, "Key unlock failed.")
                session.clear()
                session.permanent = True
                session["uid"] = user["id"]
                sid = secrets.token_hex(16)
                session["sid"] = sid
                _ks_put(sid, priv)
                g.user = user
                audit.log("LOGIN", True)
                return redirect(url_for("dashboard"))
            if user:
                fails = user["failed_attempts"] + 1
                locked = None
                if fails >= app.config["MAX_FAILED_LOGINS"]:
                    locked = (datetime.now(timezone.utc) + timedelta(
                        minutes=app.config["LOCKOUT_MINUTES"])).isoformat(timespec="seconds")
                    fails = 0
                db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                           (fails, locked, user["id"]))
                db.commit()
            audit.log("LOGIN", False, username=uname)
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        if g.user:
            audit.log("LOGOUT", True)
        _ks_drop(session.get("sid"))
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------- dashboard
    @app.route("/dashboard")
    @login_required
    def dashboard():
        db = database.get_db()
        files = db.execute("SELECT * FROM files WHERE owner_id=? ORDER BY id DESC",
                           (g.user["id"],)).fetchall()
        shares = db.execute(
            "SELECT s.*, u.username AS recipient FROM shares s "
            "JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.recipient_id "
            "WHERE f.owner_id=? ORDER BY s.id DESC", (g.user["id"],)).fetchall()
        by_file = {}
        for s in shares:
            by_file.setdefault(s["file_id"], []).append(s)
        received = db.execute(
            "SELECT s.*, f.original_name, f.size, u.username AS owner FROM shares s "
            "JOIN files f ON f.id=s.file_id JOIN users u ON u.id=f.owner_id "
            "WHERE s.recipient_id=? AND s.revoked=0 ORDER BY s.id DESC",
            (g.user["id"],)).fetchall()
        return render_template("dashboard.html", files=files, by_file=by_file,
                               received=received)

    # ---------------------------------------------------------- upload
    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Choose a file to upload.", "warning")
            return redirect(url_for("dashboard"))
        name = secure_filename(f.filename) or "file"
        data = f.read()
        if not data:
            flash("Empty files are not allowed.", "warning")
            return redirect(url_for("dashboard"))
        stored = uuid.uuid4().hex + ".enc"
        aes_key, blob = cu.encrypt_bytes(data, stored.encode())          # AES-256-GCM
        wrapped = cu.wrap_key(g.user["public_key"], aes_key)              # RSA-OAEP
        with open(file_path(stored), "wb") as fh:
            fh.write(blob)
        db = database.get_db()
        cur = db.execute(
            "INSERT INTO files (owner_id,original_name,stored_name,size,sha256,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (g.user["id"], name, stored, len(data), hashlib.sha256(data).hexdigest(),
             audit.now_iso()))
        db.execute("INSERT INTO file_keys VALUES (?,?,?)", (cur.lastrowid, g.user["id"], wrapped))
        db.commit()
        audit.log("UPLOAD", True, target=f"file:{cur.lastrowid}", details=f"{name} ({len(data)} B)")
        flash(f"'{name}' encrypted and stored.", "success")
        return redirect(url_for("dashboard"))

    # -------------------------------------------------------- download
    @app.route("/download/<int:file_id>")
    @login_required
    def download(file_id):
        db = database.get_db()
        f = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        target = f"file:{file_id}"
        if f is None:
            audit.log("DOWNLOAD", False, target=target, details="not found")
            abort(404, "File not found.")
        share = None
        if f["owner_id"] != g.user["id"]:
            share = db.execute(
                "SELECT * FROM shares WHERE file_id=? AND recipient_id=? AND revoked=0 "
                "ORDER BY id DESC LIMIT 1", (file_id, g.user["id"])).fetchone()
            if share is None or share_status(share) != "active":
                audit.log("DOWNLOAD", False, target=target, details="access denied")
                abort(403, "You are not authorised to access this file.")
        priv = _ks_get(session.get("sid"))
        if priv is None:
            audit.log("DOWNLOAD", False, target=target, details="key session expired")
            _ks_drop(session.get("sid"))
            session.clear()
            flash("Your key session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        fk = db.execute("SELECT wrapped_key FROM file_keys WHERE file_id=? AND user_id=?",
                        (file_id, g.user["id"])).fetchone()
        if fk is None:
            audit.log("DOWNLOAD", False, target=target, details="no key")
            abort(403, "You are not authorised to access this file.")
        try:
            aes_key = cu.unwrap_key(priv, fk["wrapped_key"])
            with open(file_path(f["stored_name"]), "rb") as fh:
                blob = fh.read()
            data = cu.decrypt_bytes(aes_key, blob, f["stored_name"].encode())
        except (cu.InvalidTag, ValueError, OSError):
            audit.log("DOWNLOAD", False, target=target, details="integrity/decryption failure")
            abort(400, "Decryption failed: the stored file is corrupted or was tampered with.")
        if share is not None:   # atomically enforce expiry + download limit
            cur = db.execute(
                "UPDATE shares SET downloads=downloads+1 WHERE id=? AND revoked=0 "
                "AND (max_downloads IS NULL OR downloads<max_downloads) "
                "AND (expires_at IS NULL OR expires_at>?)", (share["id"], audit.now_iso()))
            db.commit()
            if cur.rowcount == 0:
                audit.log("DOWNLOAD", False, target=target, details="share limit reached")
                abort(403, "This share has expired or reached its download limit.")
        audit.log("DOWNLOAD", True, target=target, details=f["original_name"])
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=f["original_name"],
                         mimetype="application/octet-stream")

    # ----------------------------------------------------------- share
    def owned_file_or_403(file_id):
        f = database.get_db().execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if f is None:
            abort(404, "File not found.")
        if f["owner_id"] != g.user["id"]:
            audit.log("OWNERSHIP_VIOLATION", False, target=f"file:{file_id}", details=request.path)
            abort(403, "Only the owner can do this.")
        return f

    @app.route("/share/<int:file_id>", methods=["GET", "POST"])
    @login_required
    def share(file_id):
        f = owned_file_or_403(file_id)
        db = database.get_db()
        if request.method == "POST":
            rname = request.form.get("recipient", "").strip()
            recipient = db.execute("SELECT * FROM users WHERE username=?", (rname,)).fetchone()
            try:
                hours = int(request.form["expiry_hours"]) if request.form.get("expiry_hours") else None
                limit = int(request.form["max_downloads"]) if request.form.get("max_downloads") else None
            except ValueError:
                hours = limit = -1
            if recipient is None or recipient["id"] == g.user["id"]:
                flash("Enter the username of another registered user.", "danger")
            elif (hours is not None and not 1 <= hours <= 8760) or \
                 (limit is not None and not 1 <= limit <= 1000):
                flash("Expiry must be 1-8760 hours and download limit 1-1000.", "danger")
            else:
                priv = _ks_get(session.get("sid"))
                if priv is None:
                    session.clear()
                    flash("Your key session expired. Please log in again.", "warning")
                    return redirect(url_for("login"))
                own = db.execute("SELECT wrapped_key FROM file_keys WHERE file_id=? AND user_id=?",
                                 (file_id, g.user["id"])).fetchone()
                aes_key = cu.unwrap_key(priv, own["wrapped_key"])
                wrapped = cu.wrap_key(recipient["public_key"], aes_key)   # re-wrap for recipient
                db.execute("UPDATE shares SET revoked=1 WHERE file_id=? AND recipient_id=?",
                           (file_id, recipient["id"]))
                db.execute("INSERT OR REPLACE INTO file_keys VALUES (?,?,?)",
                           (file_id, recipient["id"], wrapped))
                exp = None
                if hours:
                    exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")
                db.execute("INSERT INTO shares (file_id,recipient_id,expires_at,max_downloads,created_at)"
                           " VALUES (?,?,?,?,?)", (file_id, recipient["id"], exp, limit, audit.now_iso()))
                db.commit()
                audit.log("SHARE", True, target=f"file:{file_id}",
                          details=f"to {rname}; expires={exp}; max={limit}")
                flash(f"Shared with {rname}.", "success")
                return redirect(url_for("dashboard"))
        return render_template("share.html", f=f)

    @app.route("/revoke/<int:share_id>", methods=["POST"])
    @login_required
    def revoke(share_id):
        db = database.get_db()
        s = db.execute("SELECT * FROM shares WHERE id=?", (share_id,)).fetchone()
        if s is None:
            abort(404)
        owned_file_or_403(s["file_id"])
        db.execute("UPDATE shares SET revoked=1 WHERE id=?", (share_id,))
        db.execute("DELETE FROM file_keys WHERE file_id=? AND user_id=?",
                   (s["file_id"], s["recipient_id"]))   # recipient loses the wrapped key
        db.commit()
        audit.log("REVOKE", True, target=f"file:{s['file_id']}", details=f"share {share_id}")
        flash("Access revoked.", "info")
        return redirect(url_for("dashboard"))

    @app.route("/delete/<int:file_id>", methods=["POST"])
    @login_required
    def delete(file_id):
        f = owned_file_or_403(file_id)
        try:
            os.remove(file_path(f["stored_name"]))
        except OSError:
            pass
        db = database.get_db()
        db.execute("DELETE FROM files WHERE id=?", (file_id,))
        db.commit()
        audit.log("DELETE", True, target=f"file:{file_id}", details=f["original_name"])
        flash("File deleted.", "info")
        return redirect(url_for("dashboard"))

    # ----------------------------------------------------------- audit
    @app.route("/audit")
    @login_required
    def audit_view():
        db = database.get_db()
        if g.user["role"] == "admin":
            rows = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 300").fetchall()
            ok, bad = audit.verify_chain()
        else:
            rows = db.execute("SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 300",
                              (g.user["id"],)).fetchall()
            ok, bad = None, None
        return render_template("audit.html", rows=rows, chain_ok=ok, bad_id=bad)

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        users = database.get_db().execute(
            "SELECT u.id,u.username,u.email,u.role,u.created_at,"
            "(SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS nfiles FROM users u").fetchall()
        return render_template("users.html", users=users)

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
