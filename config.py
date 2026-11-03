import os
from datetime import timedelta


class Config:
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024          # 16 MB upload limit
    SECRET_KEY = os.environ.get("SECRET_KEY")
    RSA_BITS = max(2048, int(os.environ.get("RSA_BITS", 3072)))
    SCRYPT_N = int(os.environ.get("SCRYPT_N", 2 ** 17))

    # Security Cookies: defaults to Secure=True (set SECURE_COOKIES=0 for local non-HTTPS development)
    SESSION_COOKIE_SECURE = os.environ.get("SECURE_COOKIES", "1") != "0"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Brute-force & Rate Limiting
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 15
    IP_RATE_LIMIT_MAX = 15
    IP_RATE_LIMIT_WINDOW = 900  # seconds (15 minutes)
