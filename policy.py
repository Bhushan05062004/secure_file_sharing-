"""Centralized enterprise IAM policy layer for SecureShare.

Defines role hierarchies, granular permissions, group memberships, and a single
authorization gate: can(user, action, resource=None).
"""
import functools
from flask import abort, current_app, g, request

import audit
import db as database

# Granular enterprise roles
ROLES = {
    "user": "Standard Employee",
    "auditor": "Security & Financial Auditor",
    "security_admin": "Information Security Administrator",
    "compliance_officer": "Data Governance & Compliance Officer",
    "it_admin": "IT Systems Administrator"
}

# Role-based static permissions (actions allowed regardless of resource ownership)
ROLE_PERMISSIONS = {
    "user": {
        "view_dashboard",
        "upload_file",
        "view_audit_logs_own",
        "change_password"
    },
    "auditor": {
        "view_dashboard",
        "view_audit_logs",
        "verify_audit_chain",
        "view_users",
        "view_groups",
        "change_password"
    },
    "security_admin": {
        "view_dashboard",
        "view_audit_logs",
        "verify_audit_chain",
        "view_users",
        "manage_users",
        "view_groups",
        "manage_groups",
        "revoke_any_share",
        "change_password"
    },
    "compliance_officer": {
        "view_dashboard",
        "view_audit_logs",
        "verify_audit_chain",
        "view_users",
        "view_groups",
        "view_compliance_reports",
        "change_password"
    },
    "it_admin": {
        "view_dashboard",
        "upload_file",
        "view_users",
        "manage_users",
        "view_groups",
        "manage_groups",
        "view_audit_logs",
        "change_password"
    }
}


def get_user_groups(user_id: int):
    """Returns a list of group names the specified user belongs to."""
    db = database.get_db()
    rows = db.execute(
        "SELECT g.id, g.name, g.description FROM groups g "
        "JOIN group_members gm ON gm.group_id=g.id "
        "WHERE gm.user_id=?",
        (user_id,)
    ).fetchall()
    return rows


def can(user, action: str, resource=None) -> bool:
    """Evaluates whether the given user has permission to execute action on resource.

    Args:
        user: dict or sqlite3.Row of the user (or None if anonymous)
        action: action identifier string (e.g. 'download_file', 'view_users')
        resource: optional resource context (e.g. file row, share row, group row)

    Returns:
        bool: True if authorized, False otherwise.
    """
    if not user:
        return False

    role = user.get("role") if isinstance(user, dict) else user["role"]
    user_id = user.get("id") if isinstance(user, dict) else user["id"]

    # 1. Global / administrative actions governed by role
    if action in ROLE_PERMISSIONS.get(role, set()):
        # Actions requiring no resource or where role grants unconditional authorization
        if resource is None:
            return True

    # 2. Resource-level actions:
    if action == "view_audit_logs":
        # Global audit logs require auditor, security_admin, compliance_officer, or it_admin
        return role in {"auditor", "security_admin", "compliance_officer", "it_admin"}

    if action == "verify_audit_chain":
        return role in {"auditor", "security_admin", "compliance_officer"}

    if action in {"view_users", "view_groups"}:
        return role in {"auditor", "security_admin", "compliance_officer", "it_admin"}

    if action in {"manage_users", "manage_groups"}:
        return role in {"security_admin", "it_admin"}

    if action == "upload_file":
        return role in {"user", "it_admin"}

    if action == "share_file":
        if not resource:
            return False
        # Only owner can share a file
        owner_id = resource.get("owner_id") if isinstance(resource, dict) else resource["owner_id"]
        return owner_id == user_id

    if action == "revoke_share":
        # Security admin can revoke any share to prevent data spillage
        if role == "security_admin":
            return True
        if not resource:
            return False
        # Owner of the file associated with the share can revoke
        owner_id = resource.get("owner_id") if isinstance(resource, dict) else resource["owner_id"]
        return owner_id == user_id

    if action == "delete_file":
        if not resource:
            return False
        owner_id = resource.get("owner_id") if isinstance(resource, dict) else resource["owner_id"]
        return owner_id == user_id

    if action == "download_file":
        if not resource:
            return False

        owner_id = resource.get("owner_id") if isinstance(resource, dict) else resource["owner_id"]
        if owner_id == user_id:
            return True

        # Check if recipient has an active share directly
        file_id = resource.get("id") if isinstance(resource, dict) else resource["id"]
        db = database.get_db()
        share = db.execute(
            "SELECT * FROM shares WHERE file_id=? AND recipient_id=? AND revoked=0 "
            "ORDER BY id DESC LIMIT 1",
            (file_id, user_id)
        ).fetchone()

        if share is not None and current_app.share_status(share) == "active":
            return True

        # Check if recipient has access via group membership
        group_share = db.execute(
            "SELECT s.* FROM shares s "
            "JOIN group_members gm ON gm.group_id=s.recipient_id "
            "WHERE s.file_id=? AND gm.user_id=? AND s.revoked=0 "
            "ORDER BY s.id DESC LIMIT 1",
            (file_id, user_id)
        ).fetchone()

        if group_share is not None and current_app.share_status(group_share) == "active":
            return True

        return False

    return False


def require_permission(action: str, resource_getter=None):
    """Route decorator enforcing can(g.user, action, resource)."""
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if g.user is None:
                abort(401)
            resource = resource_getter(*args, **kwargs) if resource_getter else None
            if not can(g.user, action, resource):
                target = f"{action}:{resource.get('id') if isinstance(resource, dict) else (resource or request.path)}"
                audit.log("PERMISSION_DENIED", False, target=target, details=f"User {g.user['username']} lacks {action}")
                abort(403, "You do not have permission to perform this action.")
            return view(*args, **kwargs)
        return wrapper
    return decorator
