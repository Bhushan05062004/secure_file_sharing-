import sqlite3
from flask import current_app, g

VALID_ROLES = ("user", "auditor", "security_admin", "compliance_officer", "it_admin")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'auditor', 'security_admin', 'compliance_officer', 'it_admin')),
    public_key TEXT NOT NULL,
    enc_private_key TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    session_nonce TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    stored_name TEXT UNIQUE NOT NULL,
    size INTEGER NOT NULL,
    content_hmac TEXT NOT NULL DEFAULT '',
    classification TEXT NOT NULL DEFAULT 'internal' CHECK(classification IN ('public', 'internal', 'confidential', 'restricted')),
    legal_hold INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS file_keys (
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key BLOB NOT NULL,
    PRIMARY KEY (file_id, user_id)
);

CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT,
    max_downloads INTEGER,
    downloads INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    ip TEXT,
    success INTEGER NOT NULL,
    details TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

-- Performance & Integrity Indexes
CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id);
CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares(recipient_id);
CREATE INDEX IF NOT EXISTS idx_shares_active ON shares(file_id, recipient_id, revoked);
CREATE INDEX IF NOT EXISTS idx_shares_expiry ON shares(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(ts);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            timeout=10.0,
            isolation_level=None  # autocommit mode; explicit BEGIN / BEGIN IMMEDIATE as needed
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(_=None):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def init_db():
    d = get_db()
    d.executescript(SCHEMA)

    # Safe column migrations for existing databases
    user_cols = [r["name"] for r in d.execute("PRAGMA table_info(users)").fetchall()]
    if "session_nonce" not in user_cols:
        d.execute("ALTER TABLE users ADD COLUMN session_nonce TEXT NOT NULL DEFAULT ''")

    # Migrate legacy 'admin' roles to 'it_admin'
    d.execute("UPDATE users SET role='it_admin' WHERE role='admin'")

    file_cols = [r["name"] for r in d.execute("PRAGMA table_info(files)").fetchall()]
    if "sha256" in file_cols:
        try:
            d.execute("ALTER TABLE files DROP COLUMN sha256")
        except sqlite3.OperationalError:
            pass
    if "content_hmac" not in file_cols:
        d.execute("ALTER TABLE files ADD COLUMN content_hmac TEXT NOT NULL DEFAULT ''")
    if "classification" not in file_cols:
        d.execute("ALTER TABLE files ADD COLUMN classification TEXT NOT NULL DEFAULT 'internal'")
    if "legal_hold" not in file_cols:
        d.execute("ALTER TABLE files ADD COLUMN legal_hold INTEGER NOT NULL DEFAULT 0")

    d.execute("CREATE INDEX IF NOT EXISTS idx_files_classification ON files(classification)")
    d.execute("CREATE INDEX IF NOT EXISTS idx_files_legal_hold ON files(legal_hold)")
