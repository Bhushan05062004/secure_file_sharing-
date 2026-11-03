"""Hybrid-encryption primitives.

* Files      : AES-256-GCM (authenticated encryption, random 96-bit nonce)
* File keys  : wrapped per user with RSA-OAEP (SHA-256)
* Private key: stored encrypted with AES-256-GCM under a key derived from the
               user's password with scrypt.
"""
import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag  # noqa: F401  (re-exported)

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


# ---------- RSA key pair ----------
def generate_rsa_keypair(bits=3072):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub_pem


def _derive(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1).derive(password.encode())


def protect_private_key(priv, password: str) -> str:
    pem = priv.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_derive(password, salt)).encrypt(nonce, pem, b"user-private-key")
    return base64.b64encode(salt + nonce + ct).decode()


def unlock_private_key(blob: str, password: str):
    raw = base64.b64decode(blob)
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    try:
        pem = AESGCM(_derive(password, salt)).decrypt(nonce, ct, b"user-private-key")
    except InvalidTag:
        raise ValueError("Cannot unlock private key")
    return serialization.load_pem_private_key(pem, password=None)


# ---------- AES-256-GCM file encryption ----------
def encrypt_bytes(data: bytes, aad: bytes):
    """Returns (aes_key, nonce||ciphertext||tag)."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return key, nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Raises InvalidTag if the ciphertext was modified."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


# ---------- RSA-OAEP key wrapping ----------
def wrap_key(public_pem: str, aes_key: bytes) -> bytes:
    pub = serialization.load_pem_public_key(public_pem.encode())
    return pub.encrypt(aes_key, _OAEP)


def unwrap_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(wrapped, _OAEP)
