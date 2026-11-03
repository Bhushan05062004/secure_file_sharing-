import functools
import io
import os
import uuid
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, send_file, session, url_for)
from werkzeug.utils import secure_filename

import audit
import crypto_utils as cu
import db as database
import policy
import services

files_bp = Blueprint("files", __name__)


def login_required(view):
    @functools.wraps(view)
    def wrapper(*a, **kw):
        if g.user is None:
            flash("Please log in.", "warning")
            return redirect(url_for("auth.login"))
        return view(*a, **kw)
    return wrapper


def file_path(stored_name):
    return os.path.join(current_app.config["STORAGE_DIR"], stored_name)


@files_bp.route("/")
def index():
    return redirect(url_for("files.dashboard") if g.user else url_for("auth.login"))


@files_bp.route("/dashboard")
@login_required
def dashboard():
    if not policy.can(g.user, "view_dashboard"):
        abort(403)

    db = database.get_db()
    services.cleanup_expired_shares(db)

    files = db.execute(
        "SELECT * FROM files WHERE owner_id=? ORDER BY id DESC",
        (g.user["id"],)
    ).fetchall()

    shares = db.execute(
        "SELECT s.*, u.username AS recipient FROM shares s "
        "JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.recipient_id "
        "WHERE f.owner_id=? ORDER BY s.id DESC",
        (g.user["id"],)
    ).fetchall()

    by_file = {}
    for s in shares:
        by_file.setdefault(s["file_id"], []).append(s)

    received = db.execute(
        "SELECT s.*, f.original_name, f.size, u.username AS owner FROM shares s "
        "JOIN files f ON f.id=s.file_id JOIN users u ON u.id=f.owner_id "
        "WHERE s.recipient_id=? AND s.revoked=0 ORDER BY s.id DESC",
        (g.user["id"],)
    ).fetchall()

    return render_template("dashboard.html", files=files, by_file=by_file, received=received)


@files_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    if not policy.can(g.user, "upload_file"):
        audit.log("PERMISSION_DENIED", False, target="upload", details=f"User {g.user['username']} cannot upload")
        abort(403, "You do not have permission to upload files.")

    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choose a file to upload.", "warning")
        return redirect(url_for("files.dashboard"))

    name = secure_filename(f.filename) or "file"
    data = f.read()
    if not data:
        flash("Empty files are not allowed.", "warning")
        return redirect(url_for("files.dashboard"))

    stored = uuid.uuid4().hex + ".enc"
    full_path = file_path(stored)

    # Bind owner_id and stored filename into AES-GCM AAD to prevent ciphertext transplantation
    aad = f"owner:{g.user['id']}|file:{stored}".encode()
    aes_key, blob = cu.encrypt_bytes(data, aad)
    wrapped = cu.wrap_key(g.user["public_key"], aes_key)

    hmac_digest = audit.content_hmac(data)
    db = database.get_db()

    # Robustness: ensure temporary or orphaned files are cleaned up if disk/DB fails
    try:
        with open(full_path, "wb") as fh:
            fh.write(blob)

        cur = db.execute(
            "INSERT INTO files (owner_id,original_name,stored_name,size,content_hmac,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (g.user["id"], name, stored, len(data), hmac_digest, audit.now_iso())
        )
        file_id = cur.lastrowid
        db.execute("INSERT INTO file_keys VALUES (?,?,?)", (file_id, g.user["id"], wrapped))
    except Exception:
        if os.path.exists(full_path):
            try:
                os.remove(full_path)
            except OSError:
                pass
        raise

    audit.log("UPLOAD", True, target=f"file:{file_id}", details=f"{name} ({len(data)} B)")
    flash(f"'{name}' encrypted and stored.", "success")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    db = database.get_db()
    services.cleanup_expired_shares(db)

    f = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    target = f"file:{file_id}"
    if f is None:
        audit.log("DOWNLOAD", False, target=target, details="not found")
        abort(404, "File not found.")

    # Granular policy authorization check via can(user, 'download_file', f)
    if not policy.can(g.user, "download_file", f):
        audit.log("DOWNLOAD", False, target=target, details="access denied")
        abort(403, "You are not authorised to access this file.")

    priv = current_app.keystore_get(session.get("sid"))
    if priv is None:
        audit.log("DOWNLOAD", False, target=target, details="key session expired")
        current_app.keystore_drop(session.get("sid"))
        session.clear()
        flash("Your key session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    fk = db.execute("SELECT wrapped_key FROM file_keys WHERE file_id=? AND user_id=?",
                    (file_id, g.user["id"])).fetchone()
    if fk is None:
        audit.log("DOWNLOAD", False, target=target, details="no key")
        abort(403, "You are not authorised to access this file.")

    try:
        aes_key = cu.unwrap_key(priv, fk["wrapped_key"])
        with open(file_path(f["stored_name"]), "rb") as fh:
            blob = fh.read()

        # Try AAD with bound owner identity first, fallback to legacy AAD for older files
        aad = f"owner:{f['owner_id']}|file:{f['stored_name']}".encode()
        try:
            data = cu.decrypt_bytes(aes_key, blob, aad)
        except cu.InvalidTag:
            data = cu.decrypt_bytes(aes_key, blob, f["stored_name"].encode())
    except (cu.InvalidTag, ValueError, OSError):
        audit.log("DOWNLOAD", False, target=target, details="integrity/decryption failure")
        abort(400, "Decryption failed: the stored file is corrupted or was tampered with.")

    # Record share download usage if downloading via share
    if f["owner_id"] != g.user["id"]:
        share = db.execute(
            "SELECT * FROM shares WHERE file_id=? AND recipient_id=? AND revoked=0 "
            "ORDER BY id DESC LIMIT 1",
            (file_id, g.user["id"])
        ).fetchone()

        if share:
            cur = db.execute(
                "UPDATE shares SET downloads=downloads+1 WHERE id=? AND revoked=0 "
                "AND (max_downloads IS NULL OR downloads<max_downloads) "
                "AND (expires_at IS NULL OR expires_at>?)",
                (share["id"], audit.now_iso())
            )
            if cur.rowcount == 0:
                audit.log("DOWNLOAD", False, target=target, details="share limit reached")
                abort(403, "This share has expired or reached its download limit.")

            # If quota reached, revoke share and delete recipient key
            updated = db.execute("SELECT downloads, max_downloads FROM shares WHERE id=?", (share["id"],)).fetchone()
            if updated and updated["max_downloads"] and updated["downloads"] >= updated["max_downloads"]:
                db.execute("UPDATE shares SET revoked=1 WHERE id=?", (share["id"],))
                db.execute("DELETE FROM file_keys WHERE file_id=? AND user_id=?", (file_id, g.user["id"]))

    audit.log("DOWNLOAD", True, target=target, details=f["original_name"])
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=f["original_name"],
        mimetype="application/octet-stream"
    )


@files_bp.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    db = database.get_db()
    f = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if f is None:
        abort(404, "File not found.")

    if not policy.can(g.user, "share_file", f):
        audit.log("OWNERSHIP_VIOLATION", False, target=f"file:{file_id}", details=request.path)
        abort(403, "Only the file owner can share this file.")

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
            priv = current_app.keystore_get(session.get("sid"))
            if priv is None:
                session.clear()
                flash("Your key session expired. Please log in again.", "warning")
                return redirect(url_for("auth.login"))

            own = db.execute("SELECT wrapped_key FROM file_keys WHERE file_id=? AND user_id=?",
                             (file_id, g.user["id"])).fetchone()
            aes_key = cu.unwrap_key(priv, own["wrapped_key"])
            wrapped = cu.wrap_key(recipient["public_key"], aes_key)  # re-wrap for recipient

            db.execute("UPDATE shares SET revoked=1 WHERE file_id=? AND recipient_id=?",
                       (file_id, recipient["id"]))
            db.execute("INSERT OR REPLACE INTO file_keys VALUES (?,?,?)",
                       (file_id, recipient["id"], wrapped))
            exp = None
            if hours:
                exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")
            db.execute(
                "INSERT INTO shares (file_id,recipient_id,expires_at,max_downloads,created_at)"
                " VALUES (?,?,?,?,?)",
                (file_id, recipient["id"], exp, limit, audit.now_iso())
            )
            audit.log("SHARE", True, target=f"file:{file_id}",
                      details=f"to {rname}; expires={exp}; max={limit}")
            flash(f"Shared with {rname}.", "success")
            return redirect(url_for("files.dashboard"))

    return render_template("share.html", f=f)


@files_bp.route("/revoke/<int:share_id>", methods=["POST"])
@login_required
def revoke(share_id):
    db = database.get_db()
    s = db.execute(
        "SELECT s.*, f.owner_id FROM shares s JOIN files f ON f.id=s.file_id WHERE s.id=?",
        (share_id,)
    ).fetchone()
    if s is None:
        abort(404)

    if not policy.can(g.user, "revoke_share", s):
        audit.log("OWNERSHIP_VIOLATION", False, target=f"share:{share_id}", details=request.path)
        abort(403, "You do not have permission to revoke this share.")

    db.execute("UPDATE shares SET revoked=1 WHERE id=?", (share_id,))
    db.execute("DELETE FROM file_keys WHERE file_id=? AND user_id=?",
               (s["file_id"], s["recipient_id"]))
    audit.log("REVOKE", True, target=f"file:{s['file_id']}", details=f"share {share_id}")
    flash("Access revoked.", "info")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    db = database.get_db()
    f = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if f is None:
        abort(404, "File not found.")

    if not policy.can(g.user, "delete_file", f):
        audit.log("OWNERSHIP_VIOLATION", False, target=f"file:{file_id}", details=request.path)
        abort(403, "Only the owner can delete this file.")

    try:
        os.remove(file_path(f["stored_name"]))
    except OSError:
        pass

    db.execute("DELETE FROM files WHERE id=?", (file_id,))
    audit.log("DELETE", True, target=f"file:{file_id}", details=f["original_name"])
    flash("File deleted.", "info")
    return redirect(url_for("files.dashboard"))
