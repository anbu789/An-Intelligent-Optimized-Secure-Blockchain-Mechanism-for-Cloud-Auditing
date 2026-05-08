import os
import time
from modules.s3_handler import upload_bytes, download_bytes
from modules.auditing import audit_file
from modules.encryption import encrypt_bytes, compute_hash
from modules.blockchain import get_hash1
from modules.preprocessor import preprocess_image, preprocess_audio

# Dataset paths
DATASET_BASE = "/home/anbuselvanmurugesan/Documents/obhsb_project/datasets"

DATASET_PATHS = {
    "text" : f"{DATASET_BASE}/text/mixed/txt_files",
    "image": f"{DATASET_BASE}/image/mixed",
    "audio": f"{DATASET_BASE}/audio/mixed",
}


def inject_attack(filename, data_type):
    """
    Simulate a DoS/injection attack — overwrite the S3 encrypted file
    with random garbage bytes. Blockchain Hash1 is NOT touched.
    """
    s3_key = f"encrypted/{data_type}/{filename}"

    # Step 1: Get original file size (1 GET)
    original_bytes = download_bytes(s3_key)
    original_size  = len(original_bytes)

    # Step 2: Generate garbage bytes — same size as original
    garbage_bytes = os.urandom(original_size)

    # Step 3: Overwrite S3 with garbage (1 PUT)
    upload_bytes(garbage_bytes, s3_key)

    result = {
        "filename"      : filename,
        "data_type"     : data_type,
        "s3_key"        : s3_key,
        "original_size" : original_size,
        "garbage_size"  : len(garbage_bytes),
        "injected_at"   : time.time(),
        "status"        : "ATTACKED"
    }

    print(f"  [DOS]   ATTACK INJECTED: {s3_key}")
    print(f"  [DOS]     Original size : {original_size} bytes")
    print(f"  [DOS]     Garbage size  : {len(garbage_bytes)} bytes")
    print(f"  [DOS]     Blockchain Hash1 → UNCHANGED (attacker cannot touch it)")

    return result


def run_dos_audit(filename, data_type):
    """
    Re-run Phase 3 audit on a tampered file.
    Expects DATA INJECTED to be detected.
    """
    print(f"\n  [DOS]  Re-running Phase 3 audit on tampered file: {filename}")

    result = audit_file(filename, data_type)

    attack_caught = result["verdict"] in ("DATA INJECTED", "BLOCKED")

    if attack_caught:
        print(f"  [DOS]  ATTACK CAUGHT — {result['verdict']}")
        print(f"  [DOS]     Hash1 (blockchain) : {result.get('hash1', 'N/A')[:20]}...")
        print(f"  [DOS]     Hash2 (S3 garbage) : {result.get('hash2', 'N/A')[:20]}...")
        print(f"  [DOS]     Fitness            : {result.get('fitness')}")
    else:
        print(f"  [DOS]  ATTACK NOT CAUGHT — verdict: {result['verdict']}")

    return {
        "filename"     : filename,
        "data_type"    : data_type,
        "attack_caught": attack_caught,
        "verdict"      : result["verdict"],
        "hash1"        : result.get("hash1", "N/A"),
        "hash2"        : result.get("hash2", "N/A"),
        "fitness"      : result.get("fitness", 0.0),
    }


def restore_file(filename, data_type):
    """
    Restore a tampered S3 file back to its original encrypted state.
    Re-encrypts from local dataset and re-uploads to S3.
    Does NOT add a new blockchain block — Hash1 already exists.
    NOTE: hash1_match will always be False — new random IV each encryption.
    """
    s3_key      = f"encrypted/{data_type}/{filename}"
    folder_path = DATASET_PATHS[data_type]

    print(f"\n  [DOS]  Restoring file: {filename}")

    raw_bytes = None

    if data_type == "text":
        file_path = os.path.join(folder_path, filename)
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

    elif data_type == "image":
        records = preprocess_image(folder_path)
        for r in records:
            if r["filename"] == filename:
                raw_bytes = r["data"]
                break

    elif data_type == "audio":
        records = preprocess_audio(folder_path)
        for r in records:
            if r["filename"] == filename:
                raw_bytes = r["data"]
                break

    if raw_bytes is None:
        print(f"  [DOS]  RESTORE FAILED — file not found in local dataset: {filename}")
        return {
            "filename"      : filename,
            "data_type"     : data_type,
            "s3_key"        : s3_key,
            "restored_hash" : None,
            "hash1_match"   : False,
            "status"        : "RESTORE_FAILED"
        }

    encrypted_bytes = encrypt_bytes(raw_bytes)
    restored_hash   = compute_hash(encrypted_bytes)
    hash1           = get_hash1(filename)

    upload_bytes(encrypted_bytes, s3_key)

    hash1_match = (restored_hash == hash1)

    print(f"  [DOS]  File restored to S3: {s3_key}")
    print(f"  [DOS]     Restored hash : {restored_hash[:20]}...")
    print(f"  [DOS]     Blockchain H1 : {hash1[:20] if hash1 else 'NOT FOUND'}...")
    print(f"  [DOS]     Hash match    : {hash1_match} (expected False — new IV each encrypt)")

    return {
        "filename"      : filename,
        "data_type"     : data_type,
        "s3_key"        : s3_key,
        "restored_hash" : restored_hash,
        "hash1_match"   : hash1_match,
        "status"        : "RESTORED"
    }
