# Secure File Sharing System Using Hybrid Encryption

**Student:** Bhushan Prakash Bhat (1RN25MC019) | **Guide:** Kavya NP | **Specialization:** Cyber Security

A Flask web application where files are encrypted with **AES-256-GCM** before storage, and the
per-file AES key is protected with **RSA-3072 (OAEP/SHA-256)**. It includes authentication,
role-based access control, ownership validation, controlled sharing (expiry + download limits),
and a tamper-evident audit log.

## Quick start
```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                     # http://127.0.0.1:5000
```
Optional admin account: `python manage.py create-admin <username> <email>`
Tests: `python -m unittest discover -s tests -v`  |  Benchmark: `python benchmark.py`
Behind HTTPS set `SECURE_COOKIES=1`.

## Workflow
Login -> Upload -> AES-256-GCM encrypt -> RSA-OAEP wrap key -> Encrypted storage -> Share
(owner's unwrapped AES key re-wrapped with recipient's public key) -> Authorization check ->
Decrypt -> Secure download -> Audit log

## Project structure
| File | Purpose |
|---|---|
| `app.py` | Flask app: routes, auth, sessions, CSRF, security headers, sharing logic |
| `crypto_utils.py` | AES-GCM, RSA-OAEP, scrypt-protected private keys |
| `db.py` | SQLite schema (users, files, file_keys, shares, audit_logs) |
| `audit.py` | Hash-chained audit log and verification |
| `services.py` | Registration validation, user + key-pair creation |
| `manage.py` | Create admin user (CLI) |
| `benchmark.py` | Encryption/decryption performance evaluation (CSV output) |
| `tests/test_app.py` | 14 security & access-control test cases |
| `templates/`, `static/` | Bootstrap UI |

## Key design
* **Each user has an RSA key pair.** The public key is stored; the private key is stored only
  encrypted (AES-GCM, key derived from the password via scrypt). It is unlocked at login and
  held in server memory for the session only.
* **Each file gets a fresh random AES-256 key** and nonce. The stored blob is
  `nonce || ciphertext || tag`; the stored filename is a random UUID and is bound as AAD.
* **`file_keys` table** holds one RSA-wrapped AES key per authorised user. Sharing adds a row;
  revoking deletes it. The file is never re-encrypted.
* **Zero-knowledge for admins:** admins can see users and the global audit log but cannot
  decrypt anyone's files (no private key access).

## Security controls (objective mapping)
| Objective | Implementation |
|---|---|
| AES-256 file encryption | `crypto_utils.encrypt_bytes` (GCM = confidentiality + integrity) |
| RSA key protection | `wrap_key` / `unwrap_key`, OAEP-SHA256 |
| Authentication | Werkzeug salted password hashes, password policy, generic errors, timing equalisation |
| Brute-force defence | Account lockout: 5 failures -> 15 min |
| RBAC + ownership | `user`/`admin` roles; owner-only share/revoke/delete; 403 + audit on violation |
| Sharing restrictions | Expiry hours, max downloads (enforced atomically in SQL), revoke |
| Audit logging | Uploads, downloads, shares, revokes, logins, failed access; SHA-256 hash chain |
| Web hardening | CSRF tokens, HttpOnly/SameSite cookies, CSP, X-Frame-Options, nosniff, 30-min sessions, 16 MB limit, `secure_filename`, parameterised SQL, auto-escaped templates |
| Tamper detection | GCM tag failure -> download refused and logged |

## Limitations (mention in viva)
* Private keys are unlocked in memory of a single server process; a restart requires re-login.
  Multi-worker deployment would need a shared secure key cache.
* Forgotten password = unrecoverable files (by design; no key escrow).
* No password-change / MFA / email verification (future work).
* Whole files are processed in memory (16 MB cap); chunked streaming would be needed for large files.
* SQLite for the prototype; the SQL is standard and can move to MySQL.

## Future work
Key escrow/rotation, MFA, chunked encryption, cloud object storage, anomaly detection on audit logs.
