from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

import audit
import db as database
import policy

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/audit")
def audit_view():
    if g.user is None:
        abort(401)

    db = database.get_db()
    ok, bad = None, None

    # Check if user has global audit viewing permission
    if policy.can(g.user, "view_audit_logs"):
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 300").fetchall()
        # Verify hash chain on-demand if user has verify_audit_chain permission
        if request.args.get("verify") == "1":
            if not policy.can(g.user, "verify_audit_chain"):
                abort(403, "You do not have permission to verify the audit chain.")
            ok, bad = audit.verify_chain()
    else:
        # Standard users can only view their own activity
        rows = db.execute(
            "SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 300",
            (g.user["id"],)
        ).fetchall()

    return render_template("audit.html", rows=rows, chain_ok=ok, bad_id=bad)


@admin_bp.route("/admin/users")
def admin_users():
    if not policy.can(g.user, "view_users"):
        audit.log("PERMISSION_DENIED", False, target=request.path, details="Access denied to users directory")
        abort(403, "Access denied.")

    users = database.get_db().execute(
        "SELECT u.id,u.username,u.email,u.role,u.created_at,"
        "(SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS nfiles FROM users u"
    ).fetchall()
    return render_template("users.html", users=users, roles=policy.ROLES)


@admin_bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
def update_user_role(user_id):
    if not policy.can(g.user, "manage_users"):
        audit.log("PERMISSION_DENIED", False, target=request.path, details="Cannot change user role")
        abort(403, "Access denied.")

    new_role = request.form.get("role", "").strip()
    if new_role not in policy.ROLES:
        flash("Invalid role specified.", "danger")
        return redirect(url_for("admin.admin_users"))

    db = database.get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        abort(404)

    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    audit.log("ROLE_CHANGE", True, target=f"user:{user_id}", details=f"{u['username']} role changed to {new_role}")
    flash(f"Updated role for '{u['username']}' to {policy.ROLES[new_role]} ({new_role}).", "success")
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/admin/groups", methods=["GET", "POST"])
def admin_groups():
    if not policy.can(g.user, "view_groups"):
        audit.log("PERMISSION_DENIED", False, target=request.path, details="Access denied to groups")
        abort(403, "Access denied.")

    db = database.get_db()
    if request.method == "POST":
        if not policy.can(g.user, "manage_groups"):
            audit.log("PERMISSION_DENIED", False, target="groups:create", details="Cannot create groups")
            abort(403, "Access denied.")

        name = request.form.get("name", "").strip()
        desc = request.form.get("description", "").strip()
        if not name:
            flash("Group name is required.", "danger")
        else:
            try:
                db.execute(
                    "INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)",
                    (name, desc, audit.now_iso())
                )
                audit.log("GROUP_CREATE", True, target=f"group:{name}")
                flash(f"Group '{name}' created.", "success")
            except Exception:
                flash(f"Group '{name}' already exists.", "danger")
        return redirect(url_for("admin.admin_groups"))

    groups = db.execute(
        "SELECT g.*, COUNT(gm.user_id) as member_count "
        "FROM groups g LEFT JOIN group_members gm ON gm.group_id=g.id "
        "GROUP BY g.id ORDER BY g.name"
    ).fetchall()

    return render_template("groups.html", groups=groups)


@admin_bp.route("/admin/groups/<int:group_id>/members", methods=["POST"])
def admin_group_members(group_id):
    if not policy.can(g.user, "manage_groups"):
        audit.log("PERMISSION_DENIED", False, target=f"group:{group_id}:members", details="Cannot manage members")
        abort(403, "Access denied.")

    db = database.get_db()
    action = request.form.get("action", "add")
    username = request.form.get("username", "").strip()

    user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        flash(f"User '{username}' not found.", "danger")
        return redirect(url_for("admin.admin_groups"))

    if action == "add":
        try:
            db.execute(
                "INSERT OR IGNORE INTO group_members (group_id, user_id, created_at) VALUES (?, ?, ?)",
                (group_id, user["id"], audit.now_iso())
            )
            audit.log("GROUP_MEMBER_ADD", True, target=f"group:{group_id}", details=f"added user:{user['id']}")
            flash(f"Added '{username}' to group.", "success")
        except Exception as e:
            flash(f"Error adding user: {e}", "danger")
    elif action == "remove":
        db.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (group_id, user["id"]))
        audit.log("GROUP_MEMBER_REMOVE", True, target=f"group:{group_id}", details=f"removed user:{user['id']}")
        flash(f"Removed '{username}' from group.", "info")

    return redirect(url_for("admin.admin_groups"))
