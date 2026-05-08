import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from config import AES_SECRET_KEY


# ─────────────────────────────────────────────
# Step 1 — Derive 32-byte AES key from .env string
# SHA-256("obhsb_secret_key_2024") → 32 bytes
# Same string always produces same key (deterministic)
# ─────────────────────────────────────────────
def _get_aes_key() -> bytes:
    return hashlib.sha256(AES_SECRET_KEY.encode('utf-8')).digest()
    # .digest() → raw bytes (32 bytes)
    # .hexdigest() would give a string — we DON'T want that here


# ─────────────────────────────────────────────
# Step 2 + 3 + 4 — Encrypt
# Input : raw bytes (text/image/audio preprocessed bytes)
# Output: IV (16 bytes) + ciphertext  ← stored in S3
# Equation (5): E* = a × k
# ─────────────────────────────────────────────
def encrypt_bytes(raw_bytes: bytes) -> bytes:
    key = _get_aes_key()                        # 32-byte key

    iv = os.urandom(16)                         # Step 2: fresh random IV every time

    cipher = AES.new(key, AES.MODE_CBC, iv)     # Step 3: AES-256-CBC cipher

    padded = pad(raw_bytes, AES.block_size)      # PKCS7 pad → multiple of 16 bytes
    ciphertext = cipher.encrypt(padded)          # encrypt

    return iv + ciphertext                       # Step 4: IV prepended to ciphertext


# ─────────────────────────────────────────────
# Step 5 — Decrypt
# Input : IV (16 bytes) + ciphertext  (what came from S3)
# Output: original raw bytes
# ─────────────────────────────────────────────
def decrypt_bytes(encrypted_bytes: bytes) -> bytes:
    key = _get_aes_key()

    iv         = encrypted_bytes[:16]            # first 16 bytes = IV
    ciphertext = encrypted_bytes[16:]            # rest = actual ciphertext

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    raw    = unpad(padded, AES.block_size)       # remove PKCS7 padding

    return raw


# ─────────────────────────────────────────────
# Step 6 — Compute SHA-256 hash
# Used for BOTH Hash1 (on encrypted bytes) and Hash2 (at audit time)
# Input : any bytes
# Output: 64-character hex string
# Equation (4): h* = a mod b
# ─────────────────────────────────────────────
def compute_hash(data_bytes: bytes) -> str:
    return hashlib.sha256(data_bytes).hexdigest()
    # hexdigest() → 64-char string like "a3f8b2c1..."
    # IMPORTANT: always call this on ENCRYPTED bytes, never raw bytes
