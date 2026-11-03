import os
from datetime import timedelta


class Config:
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024          # 16 MB upload limit
    RSA_BITS = int(os.environ.get("RSA_BITS", 3072))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Set SECURE_COOKIES=1 when running behind HTTPS
    SESSION_COOKIE_SECURE = os.environ.get("SECURE_COOKIES") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 15
