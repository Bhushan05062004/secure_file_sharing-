"""Hybrid-encryption primitives.

* Files      : AES-256-GCM (authenticated encryption, random 96-bit nonce)
* File keys  : wrapped per user with RSA-OAEP (SHA-256)
* Private key: stored encrypted with AES-256-GCM under a key derived from the
               user's password with scrypt (default n=2**17).
"""
import base64
import math
import os

from cryptography.exceptions import InvalidTag  # noqa: F401  (re-exported)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)

MIN_RSA_BITS = 2048
DEFAULT_SCRYPT_N = 2 ** 17  # 131,072 iterations for strong brute-force resistance


# ---------- RSA key pair ----------
def generate_rsa_keypair(bits=3072):
    if bits < MIN_RSA_BITS:
        raise ValueError(f"RSA key size must be at least {MIN_RSA_BITS} bits (requested {bits}).")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub_pem


def _derive(password: str, salt: bytes, n: int = DEFAULT_SCRYPT_N) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(password.encode())


def protect_private_key(priv, password: str, n: int = DEFAULT_SCRYPT_N) -> str:
    """Encrypts private key PEM with AES-256-GCM using scrypt-derived key.
    Prepends version byte 0x01 and log2(n) for flexible parameter tuning."""
    pem = priv.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    salt, nonce = os.urandom(16), os.urandom(12)
    derived = _derive(password, salt, n=n)
    ct = AESGCM(derived).encrypt(nonce, pem, b"user-private-key")
    log2_n = int(math.log2(n))
    payload = bytes([0x01, log2_n]) + salt + nonce + ct
    return base64.b64encode(payload).decode()


def unlock_private_key(blob: str, password: str):
    raw = base64.b64decode(blob)
    if len(raw) < 28:
        raise ValueError("Invalid private key blob.")

    # Check for versioned format (0x01 prefix followed by log2(n))
    if len(raw) > 30 and raw[0] == 0x01:
        log2_n = raw[1]
        n = 1 << log2_n
        salt = raw[2:18]
        nonce = raw[18:30]
        ct = raw[30:]
        try:
            pem = AESGCM(_derive(password, salt, n=n)).decrypt(nonce, ct, b"user-private-key")
        except InvalidTag:
            raise ValueError("Cannot unlock private key")
        return serialization.load_pem_private_key(pem, password=None)

    # Legacy format fallback (salt:16, nonce:12, ct): try 2**17 then 2**14
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    for n_try in (DEFAULT_SCRYPT_N, 2 ** 14):
        try:
            pem = AESGCM(_derive(password, salt, n=n_try)).decrypt(nonce, ct, b"user-private-key")
            return serialization.load_pem_private_key(pem, password=None)
        except InvalidTag:
            continue
    raise ValueError("Cannot unlock private key")


# ---------- AES-256-GCM file encryption ----------
def encrypt_bytes(data: bytes, aad: bytes):
    """Returns (aes_key, nonce||ciphertext||tag)."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return key, nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Raises InvalidTag if the ciphertext was modified or AAD doesn't match."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


# ---------- RSA-OAEP key wrapping ----------
def wrap_key(public_pem: str, aes_key: bytes) -> bytes:
    pub = serialization.load_pem_public_key(public_pem.encode())
    return pub.encrypt(aes_key, _OAEP)


def unwrap_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(wrapped, _OAEP)
