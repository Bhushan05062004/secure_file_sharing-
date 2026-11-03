import functools
import os
import secrets
import threading
import time

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import audit
import db as database
import policy
from blueprints.admin import admin_bp
from blueprints.auth import auth_bp
from blueprints.files import files_bp
from config import Config

# In-memory store of unlocked RSA private keys, keyed by session id.
# Never written to disk; cleared on logout / expiry / server restart.
# NOTE: Multi-worker deployments (e.g. Gunicorn/uWSGI) require sticky sessions
# or a shared secure key cache (e.g. Redis with TLS and KMS encryption).
_KEYSTORE, _KS_LOCK, _KEY_TTL = {}, threading.Lock(), 30 * 60


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
    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)

    if test_config:
        app.config.update(test_config)

    # ProxyFix for secure reverse proxy deployments behind Nginx/Caddy/Traefik
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Secret key loading
    if not app.config.get("SECRET_KEY"):
        key_file = os.path.join(app.instance_path, "secret.key")
        if not os.path.exists(key_file):
            with open(key_file, "w") as fh:
                fh.write(secrets.token_hex(32))
            try:
                os.chmod(key_file, 0o600)
            except OSError:
                pass
        with open(key_file) as fh:
            app.config["SECRET_KEY"] = fh.read().strip()

    # Expose keystore methods on app
    app.keystore_put = _ks_put
    app.keystore_get = _ks_get
    app.keystore_drop = _ks_drop

    app.teardown_appcontext(database.close_db)
    with app.app_context():
        database.init_db()

    # ------------------------------------------------------------ helpers
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    # Smart url_for to support legacy un-prefixed endpoint names in templates
    alias_map = {
        "index": "files.index",
        "dashboard": "files.dashboard",
        "upload": "files.upload",
        "download": "files.download",
        "share": "files.share",
        "revoke": "files.revoke",
        "delete": "files.delete",
        "login": "auth.login",
        "register": "auth.register",
        "logout": "auth.logout",
        "change_password_view": "auth.change_password_view",
        "audit_view": "admin.audit_view",
        "admin_users": "admin.admin_users",
        "admin_groups": "admin.admin_groups",
        "toggle_legal_hold": "files.toggle_legal_hold",
        "switch_role": "auth.switch_role",
        "update_user_role": "admin.update_user_role",
    }

    def smart_url_for(endpoint, **values):
        target = alias_map.get(endpoint, endpoint)
        return url_for(target, **values)

    app.jinja_env.globals["url_for"] = smart_url_for
    app.jinja_env.globals["can"] = lambda action, resource=None: policy.can(g.user, action, resource)
    app.jinja_env.globals["CLASSIFICATIONS"] = policy.CLASSIFICATIONS
    app.jinja_env.globals["ROLES"] = policy.ROLES
    app.can = policy.can

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
    app.share_status = share_status

    def fmt_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    app.jinja_env.filters["size"] = fmt_size

    def login_required(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if g.user is None:
                flash("Please log in.", "warning")
                return redirect(url_for("auth.login"))
            return view(*a, **kw)
        return wrapper

    app.login_required = login_required

    # ------------------------------------------------- Blueprints registration
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)

    # Alias endpoints for backward compatibility across templates and tests
    aliases = [
        ("login", "auth.login"),
        ("register", "auth.register"),
        ("logout", "auth.logout"),
        ("change_password_view", "auth.change_password_view"),
        ("dashboard", "files.dashboard"),
        ("upload", "files.upload"),
        ("download", "files.download"),
        ("share", "files.share"),
        ("revoke", "files.revoke"),
        ("delete", "files.delete"),
        ("index", "files.index"),
        ("audit_view", "admin.audit_view"),
        ("admin_users", "admin.admin_users"),
        ("admin_groups", "admin.admin_groups"),
        ("toggle_legal_hold", "files.toggle_legal_hold"),
        ("switch_role", "auth.switch_role"),
        ("update_user_role", "admin.update_user_role"),
    ]
    for alias, target in aliases:
        if target in app.view_functions:
            app.view_functions[alias] = app.view_functions[target]

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
            else:
                # Server-side session nonce validation: invalidates replayed cookies after logout/pw change
                nonce = session.get("nonce", "")
                if not nonce or not secrets.compare_digest(g.user["session_nonce"], nonce):
                    _ks_drop(session.get("sid"))
                    session.clear()
                    g.user = None

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
        # Strict CSP: no inline script or style execution
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        if app.config.get("SESSION_COOKIE_SECURE", True):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def http_error(e):
        msg = {
            413: "File too large (limit 16 MB).",
            429: "Too many requests. Please try again later."
        }.get(e.code, getattr(e, "description", "An error occurred."))
        return render_template("error.html", code=e.code, message=msg), e.code

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
