"""
auditing.py — OBHSB Phase 3 Cloud Auditing
===========================================
Implements the full cloud auditing pipeline:

  Step 1 — Download encrypted file from S3
  Step 2 — Buffalo Pa* check on encrypted bytes
  Step 3 — Compute Hash2 = SHA-256(encrypted_bytes)   [Equation 6]
  Step 4 — Fetch Hash1 from blockchain                 [Equation 4]
  Step 5 — Key matching: Hash1 == Hash2?               [Equation 7]
  Step 6 — Decrypt if matched
  Step 7 — Save audit log to JSON

KEY RULES:
  - Hash1 = SHA-256(encrypted_bytes) stored at upload time (immutable)
  - Hash2 = SHA-256(downloaded encrypted_bytes) computed fresh every access
  - Hash1 == Hash2 → FILE ACCESSED 
  - Hash1 != Hash2 → DATA INJECTED 
  - Buffalo WAAH   → file deleted from S3, access blocked 
"""

import json
import logging
import os
import numpy as np
from datetime import datetime
from pathlib import Path

from modules.s3_handler  import download_bytes, delete_file
from modules.encryption  import compute_hash, decrypt_bytes
from modules.blockchain  import get_hash1
from modules.buffalo     import pa_star_b3

# ── logging ───────────────────────────────────────────────────────────────────
log = logging.getLogger(__name__)

# ── paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
PROFILES_DIR = PROJECT_ROOT / "profiles"
AUDIT_LOG_DIR = PROJECT_ROOT / "outputs" / "audit_logs"

# ── profile filenames ─────────────────────────────────────────────────────────
PROFILE_FILES = {
    "text" : "text_normal_profile.npy",
    "image": "image_normal_profile.npy",
    "audio": "audio_normal_profile.npy",
}


# ── Custom Exceptions ─────────────────────────────────────────────────────────

class AuditBlockedError(Exception):
    """Raised when Buffalo says WAAH — file deleted from S3."""
    pass


class TamperDetectedError(Exception):
    """Raised when Hash1 != Hash2 — DATA INJECTED."""
    pass


# ── Step 1 — Download from S3 ─────────────────────────────────────────────────

def download_from_s3(filename: str, data_type: str) -> bytes:
    """
    Step 1 — Download encrypted file bytes from S3.

    Args:
        filename  : e.g. "ham_0001.txt"
        data_type : "text" | "image" | "audio"

    Returns:
        encrypted_bytes — IV(16 bytes) + ciphertext
    """
    s3_key = f"encrypted/{data_type}/{filename}"
    log.info(f"[STEP 1] Downloading s3://{s3_key}")
    encrypted_bytes = download_bytes(s3_key)
    log.info(f"[STEP 1] Downloaded {len(encrypted_bytes)} bytes")
    return encrypted_bytes


# ── Step 2 — Buffalo Pa* check ────────────────────────────────────────────────

def buffalo_access_check(
    filename       : str,
    data_type      : str,
    encrypted_bytes: bytes,
    normal_profile : np.ndarray,
) -> dict:
    """
    Step 2 — Run Buffalo Pa* on downloaded encrypted bytes.

    If WAAH → delete file from S3 immediately and raise AuditBlockedError.
    If MAAA → return Pa* result dict and continue.

    Args:
        filename        : e.g. "ham_0001.txt"
        data_type       : "text" | "image" | "audio"
        encrypted_bytes : bytes downloaded from S3
        normal_profile  : numpy array (32,) from profiles/

    Returns:
        pa_result dict (signal, verdict, fitness, threshold, ...)

    Raises:
        AuditBlockedError if Buffalo signals WAAH
    """
    log.info(f"[STEP 2] Running Buffalo Pa* on {filename}")
    # Always use "text" threshold (0.7) in audit mode — encrypted bytes
    # are uniform random-looking regardless of content type.
    # Real integrity check is done via key matching (Hash1 vs Hash2).
    pa_result = pa_star_b3(encrypted_bytes, normal_profile, data_type="text")

    log.info(
        f"[STEP 2] fitness={pa_result['fitness']:.4f} "
        f"threshold={pa_result['threshold']} "
        f"signal={pa_result['signal']}"
    )

    if pa_result["signal"] == "WAAH":
        # Delete malicious file from S3
        s3_key = f"encrypted/{data_type}/{filename}"
        log.warning(f"[STEP 2] WAAH — deleting malicious file from S3: {s3_key}")
        delete_file(s3_key)
        raise AuditBlockedError(
            f"Buffalo blocked '{filename}' "
            f"(fitness={pa_result['fitness']:.4f} < threshold={pa_result['threshold']}). "
            f"File deleted from S3."
        )

    log.info(f"[STEP 2] MAAA — file passed Buffalo check ")
    return pa_result


# ── Step 3 — Compute Hash2 ────────────────────────────────────────────────────

def compute_hash2(encrypted_bytes: bytes) -> str:
    """
    Step 3 — Compute Hash2 = SHA-256(encrypted_bytes).  [Equation 6]

    This reflects the CURRENT state of the file in S3.
    If an attacker changed even 1 byte, Hash2 will be completely different.

    Args:
        encrypted_bytes : raw bytes downloaded from S3

    Returns:
        hash2 — 64 char hex string
    """
    hash2 = compute_hash(encrypted_bytes)
    log.info(f"[STEP 3] Hash2 = {hash2}")
    return hash2


# ── Step 4 — Fetch Hash1 from blockchain ─────────────────────────────────────

def fetch_hash1(filename: str) -> str:
    """
    Step 4 — Fetch Hash1 from blockchain.  [Equation 4]

    Hash1 was stored at upload time (Phase 1). It is immutable —
    no attacker can change it because blockchain is append-only.

    Args:
        filename : e.g. "ham_0001.txt"

    Returns:
        hash1 — 64 char hex string

    Raises:
        ValueError if filename not found in blockchain
    """
    hash1 = get_hash1(filename)
    if hash1 is None:
        raise ValueError(
            f"Hash1 not found in blockchain for '{filename}'. "
            f"Was this file uploaded via the upload pipeline?"
        )
    log.info(f"[STEP 4] Hash1 = {hash1}")
    return hash1


# ── Step 5 — Key Matching ─────────────────────────────────────────────────────

def key_matching(hash1: str, hash2: str, filename: str) -> bool:
    """
    Step 5 — Key matching: Hash1 == Hash2?  [Equation 7]

    km = if h* == h** → FILE ACCESSED
         else         → DATA INJECTED

    Args:
        hash1    : from blockchain (immutable)
        hash2    : from S3 (current state)
        filename : for logging only

    Returns:
        True if matched

    Raises:
        TamperDetectedError if Hash1 != Hash2
    """
    matched = hash1 == hash2

    if matched:
        log.info(f"[STEP 5]  Hash1 == Hash2 — FILE ACCESSED: {filename}")
    else:
        log.warning(f"[STEP 5]  Hash1 != Hash2 — DATA INJECTED: {filename}")
        raise TamperDetectedError(
            f"Tamper detected on '{filename}'. "
            f"Hash1={hash1[:16]}... != Hash2={hash2[:16]}..."
        )

    return matched


# ── Step 6 — Decrypt ─────────────────────────────────────────────────────────

def decrypt_file(encrypted_bytes: bytes, filename: str) -> bytes:
    """
    Step 6 — AES-256 decrypt the encrypted bytes.

    Only called after key matching passes.
    IV(16 bytes) is stripped automatically inside decrypt_bytes().

    Args:
        encrypted_bytes : IV(16) + ciphertext from S3
        filename        : for logging only

    Returns:
        plaintext bytes
    """
    log.info(f"[STEP 6] Decrypting {filename}")
    plaintext = decrypt_bytes(encrypted_bytes)
    log.info(f"[STEP 6] Decrypted {len(encrypted_bytes)} → {len(plaintext)} bytes")
    return plaintext


# ── Step 7 — Save Audit Log ───────────────────────────────────────────────────

def save_audit_log(audit_result: dict) -> str:
    """
    Step 7 — Save audit result to JSON file.

    Always called regardless of outcome (ACCESSED, INJECTED, BLOCKED).

    Args:
        audit_result : dict with all audit fields

    Returns:
        path to saved JSON file
    """
    AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)

    filename  = audit_result["filename"]
    timestamp = audit_result["timestamp"].replace(":", "-")
    log_path  = AUDIT_LOG_DIR / f"audit_{filename}_{timestamp}.json"

    with open(log_path, "w") as f:
        json.dump(audit_result, f, indent=2)

    log.info(f"[STEP 7] Audit log saved → {log_path}")
    return str(log_path)


# ── Helper — load normal profile ─────────────────────────────────────────────

def load_normal_profile(data_type: str) -> np.ndarray:
    """
    Load the normal profile .npy file for the given data_type.

    Args:
        data_type : "text" | "image" | "audio"

    Returns:
        numpy array (32,)

    Raises:
        FileNotFoundError if profile not built yet
    """
    if data_type not in PROFILE_FILES:
        raise ValueError(f"Unknown data_type '{data_type}'. Must be text/image/audio.")

    profile_path = PROFILES_DIR / PROFILE_FILES[data_type]

    if not profile_path.exists():
        raise FileNotFoundError(
            f"Profile not found: {profile_path}. "
            f"Run build_profiles.py first to generate normal profiles."
        )

    return np.load(str(profile_path))


# ── Master Function — audit_file() ───────────────────────────────────────────

def audit_file(filename: str, data_type: str) -> dict:
    """
    Master audit function — runs all 7 steps in order.

    Args:
        filename  : e.g. "ham_0001.txt"
        data_type : "text" | "image" | "audio"

    Returns:
        audit_result dict:
        {
          filename, data_type, timestamp, s3_key,
          buffalo, fitness, hash1, hash2,
          key_match, verdict, action_taken,
          plaintext (bytes, only on FILE ACCESSED),
          log_path
        }

    Raises:
        AuditBlockedError   — if Buffalo says WAAH
        TamperDetectedError — if Hash1 != Hash2
        ValueError          — if filename not in blockchain
        FileNotFoundError   — if profile missing
    """
    timestamp = datetime.now().isoformat(timespec="seconds")
    s3_key    = f"encrypted/{data_type}/{filename}"

    log.info(f"\n{'='*60}")
    log.info(f"  AUDIT START : {filename} [{data_type}]")
    log.info(f"  Timestamp   : {timestamp}")
    log.info(f"{'='*60}")

    # initialise result
    audit_result = {
        "filename"    : filename,
        "data_type"   : data_type,
        "timestamp"   : timestamp,
        "s3_key"      : s3_key,
        "buffalo"     : None,
        "fitness"     : None,
        "hash1"       : None,
        "hash2"       : None,
        "key_match"   : None,
        "verdict"     : None,
        "action_taken": None,
        "log_path"    : None,
    }

    try:
        # Load normal profile
        normal_profile = load_normal_profile(data_type)

        # Step 1 — Download from S3
        encrypted_bytes = download_from_s3(filename, data_type)

        # Step 2 — Buffalo Pa* check
        pa_result = buffalo_access_check(
            filename        = filename,
            data_type       = data_type,
            encrypted_bytes = encrypted_bytes,
            normal_profile  = normal_profile,
        )
        audit_result["buffalo"] = pa_result["signal"]
        audit_result["fitness"] = round(pa_result["fitness"], 4)

        # Step 3 — Compute Hash2
        hash2 = compute_hash2(encrypted_bytes)
        audit_result["hash2"] = hash2

        # Step 4 — Fetch Hash1 from blockchain
        hash1 = fetch_hash1(filename)
        audit_result["hash1"] = hash1

        # Step 5 — Key matching
        key_matching(hash1, hash2, filename)
        audit_result["key_match"] = True
        audit_result["verdict"]   = "FILE ACCESSED"

        # Step 6 — Decrypt
        plaintext = decrypt_file(encrypted_bytes, filename)
        audit_result["action_taken"] = "DECRYPTED"
        audit_result["plaintext"]    = plaintext.decode("utf-8", errors="replace")

    except AuditBlockedError as e:
        audit_result["buffalo"]     = "WAAH"
        audit_result["verdict"]     = "BLOCKED"
        audit_result["action_taken"] = "DELETED_FROM_S3"
        log.warning(f"AUDIT BLOCKED: {e}")

    except TamperDetectedError as e:
        audit_result["key_match"]    = False
        audit_result["verdict"]      = "DATA INJECTED"
        audit_result["action_taken"] = "ACCESS DENIED"
        log.warning(f"TAMPER DETECTED: {e}")

    except Exception as e:
        audit_result["verdict"]      = "ERROR"
        audit_result["action_taken"] = str(e)
        log.error(f"AUDIT ERROR: {e}")

    finally:
        # Step 7 — Save audit log always
        log_path = save_audit_log(audit_result)
        audit_result["log_path"] = log_path

    log.info(f"  AUDIT END   : {audit_result['verdict']}")
    log.info(f"{'='*60}\n")

    return audit_result


# ── Quick test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level  = logging.INFO,
        format = "%(asctime)s  %(levelname)-8s  %(message)s",
    )

    # Test 1 — normal ham file (should pass)
    print("\n--- Test 1: Normal ham file ---")
    result = audit_file("ham_0001.txt", "text")
    print(f"Verdict : {result['verdict']}")
    print(f"Content : {result.get('plaintext', 'N/A')}")
