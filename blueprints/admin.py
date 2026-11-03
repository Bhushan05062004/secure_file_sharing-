import functools

from flask import Blueprint, abort, g, render_template, request

import audit
import db as database

admin_bp = Blueprint("admin", __name__)


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*a, **kw):
        if g.user is None or g.user["role"] != "admin":
            audit.log("ADMIN_ACCESS_DENIED", False, target=request.path)
            abort(403)
        return view(*a, **kw)
    return wrapper


@admin_bp.route("/audit")
def audit_view():
    if g.user is None:
        abort(403)

    db = database.get_db()
    ok, bad = None, None

    if g.user["role"] == "admin":
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 300").fetchall()
        # Only verify chain upon explicit request to prevent performance degradation
        if request.args.get("verify") == "1":
            ok, bad = audit.verify_chain()
    else:
        rows = db.execute("SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 300",
                          (g.user["id"],)).fetchall()

    return render_template("audit.html", rows=rows, chain_ok=ok, bad_id=bad)


@admin_bp.route("/admin/users")
@admin_required
def admin_users():
    users = database.get_db().execute(
        "SELECT u.id,u.username,u.email,u.role,u.created_at,"
        "(SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS nfiles FROM users u"
    ).fetchall()
    return render_template("users.html", users=users)
