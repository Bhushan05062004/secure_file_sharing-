# Secure File Sharing System Using Hybrid Encryption

**Student:** Bhushan Prakash Bhat (1RN25MC019) | **Guide:** Kavya NP | **Specialization:** Cyber Security

A hardened Flask web application where files are encrypted with **AES-256-GCM** before storage, and the per-file AES key is protected with **RSA-3072 (OAEP/SHA-256)**. It includes strong password derivation with scrypt, role-based access control, ownership validation, controlled sharing (expiry + download limits), and an HMAC-chained audit log with external keying.

## Quick start
```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
export SECRET_KEY="your-random-production-secret-key"
python app.py                     # http://127.0.0.1:5000
```

> **Note on Cookies:** `SESSION_COOKIE_SECURE` defaults to `True`. When developing locally without HTTPS, set `SECURE_COOKIES=0`.

* Optional admin account: `python manage.py create-admin <username> <email>`
* Run tests: `python -m pytest tests/ -v`
* Benchmark crypto: `python benchmark.py`

## Architecture & Workflow
Login -> Upload -> AES-256-GCM encrypt with bound AAD -> RSA-OAEP wrap key -> Encrypted storage -> Share (owner's unwrapped AES key re-wrapped with recipient's public key) -> Authorization check -> Decrypt -> Secure download -> HMAC Audit log

## Project structure
| File / Directory | Purpose |
|---|---|
| `app.py` | Flask application factory, ProxyFix, middleware, keystore, security headers |
| `blueprints/auth.py` | Registration, login rate limiting, atomic lockout, session nonce rotation, password change |
| `blueprints/files.py` | Dashboard, file upload with bound GCM AAD, downloads, sharing, deletion |
| `blueprints/admin.py` | Admin views: registered users, on-demand HMAC audit chain verification |
| `crypto_utils.py` | AES-256-GCM (bound AAD), RSA-OAEP, scrypt key derivation (n=2¹⁷, min 2048-bit RSA) |
| `db.py` | SQLite schema with WAL mode, foreign keys, and performance indexes |
| `audit.py` | HMAC-SHA256 chained audit log (external key, `BEGIN IMMEDIATE` concurrency safety) |
| `services.py` | User registration, password change key re-encryption, expired share cleanup |
| `manage.py` | CLI admin creation with uniqueness validation |
| `benchmark.py` | AES-GCM vs RSA performance evaluation (CSV output) |
| `tests/test_app.py` | Comprehensive test suite covering authentication, crypto, and access controls |
| `templates/`, `static/` | Strict CSP-compliant UI (no inline `<script>` or `style="..."` attributes) |

## Trust Model & Design Clarifications
* **Zero Plaintext at Rest:** Files are encrypted with random 256-bit AES keys and authenticated nonces before touching disk. User private keys are protected with scrypt (`n=131072`) and AES-256-GCM.
* **Server-Assisted Envelope Decryption (Not Client Zero-Knowledge):** The server temporarily decrypts the user's RSA private key into process memory during authenticated sessions to re-wrap file keys and serve downloads. Admins have no database or disk access to plaintext files or keys.
* **Session Invalidation:** Every user record stores an atomic `session_nonce`. On logout or password change, this nonce is regenerated, immediately invalidating copied or replayed session cookies.
* **Tamper-Evident Audit Chain:** Audit rows are chained via HMAC-SHA256 under a key stored outside the database (`instance/audit.key`), preventing offline chain modification.

## Security Controls
| Control | Implementation |
|---|---|
| AES-256 File Encryption | `AESGCM(256)` with AAD bound to `owner_id` and `stored_name` |
| RSA Key Protection | RSA-OAEP with SHA-256, minimum 2048-bit key size enforced |
| Key Derivation | Scrypt with `n=2**17` (131,072), `r=8`, `p=1` |
| Authentication Hardening | Salted password hashes, atomic SQL failed-attempt counter, uniform 401 error message (no user-enumeration or lockout leakage) |
| Rate Limiting | Sliding-window per-IP rate limiting (429 on abuse) |
| Web Hardening | Strict CSP (`object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, no inline scripts/styles), HSTS, nosniff, DENY framing, HttpOnly/SameSite cookies, Werkzeug ProxyFix |
| Database Integrity | SQLite WAL mode, foreign key cascade, index acceleration, `BEGIN IMMEDIATE` for audit writes |
| Share Lifecycle | Download quotas, expiration dates, immediate key deletion on revoke or expiration |

## Deployment Considerations
* **Multi-Worker WSGI:** The in-memory keystore (`_KEYSTORE`) holds unlocked private keys per session within process memory. Deployments running multiple worker processes (e.g., Gunicorn or uWSGI) must use **sticky sessions (session affinity)** or externalize session keys to a secure cache (e.g., Redis with mTLS and KMS envelope encryption).
* **Reverse Proxy:** The app uses `ProxyFix(x_for=1, x_proto=1, x_host=1, x_prefix=1)` to safely read client IP addresses behind Nginx, Caddy, or cloud load balancers.
* **Key Recovery:** If a user loses their password, their encrypted files cannot be decrypted (by design; no key escrow backdoor).

## License
MIT License - see [LICENSE](LICENSE).
