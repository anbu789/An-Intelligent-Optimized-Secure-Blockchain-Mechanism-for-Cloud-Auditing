"""
pipeline_phase1.py
The complete Phase 1 pipeline — wires Tasks 1, 2, 3 together.

Flow for every file:
  raw_bytes → encrypt → hash1 → blockchain → S3

Usage:
  from pipeline_phase1 import run_text_pipeline, run_image_pipeline, run_audio_pipeline
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.preprocessor import preprocess_text, preprocess_image, preprocess_audio
from modules.encryption   import encrypt_bytes, compute_hash
from modules.blockchain   import init_chain, add_block
from modules.s3_handler   import upload_encrypted_file


# ─────────────────────────────────────────────
# CORE PIPELINE — run_pipeline()
#
# Input : records   = list of dicts from any preprocessor
#                     { filename, data(raw bytes), type, size }
#         data_type = "text" / "image" / "audio"
#         limit     = max files to process (None = all)
#                     use limit=5 for testing, None for full run
#
# Output: list of result dicts per file:
#         { filename, data_type, hash1, block_index, s3_key, file_size }
# ─────────────────────────────────────────────
def run_pipeline(records: list, data_type: str, limit: int = None) -> list:

    # Ensure blockchain DB + genesis block exist
    init_chain()

    if limit:
        records = records[:limit]

    results = []
    total   = len(records)

    print(f"\n  [pipeline] Starting {data_type} pipeline — {total} files")
    print(f"  {'─'*50}")

    for i, record in enumerate(records, 1):
        filename  = record["filename"]
        raw_bytes = record["data"]

        try:
            # ── STEP 2: Encrypt raw bytes ──────────────────
            # encrypt_bytes() → IV(16) + ciphertext
            # Equation (5): E* = a × k
            encrypted_bytes = encrypt_bytes(raw_bytes)

            # ── STEP 3: Compute Hash1 ──────────────────────
            # CRITICAL: Hash1 = SHA-256(ENCRYPTED bytes) — NOT raw bytes
            # Equation (4): h* = a mod b
            hash1 = compute_hash(encrypted_bytes)

            # ── STEP 4: Store in Blockchain ────────────────
            # Blockchain written BEFORE S3 upload
            # So if S3 fails, Hash1 is still safely recorded
            block_index = add_block(
                filename  = filename,
                hash1     = hash1,
                data_type = data_type,
                file_size = len(encrypted_bytes)
            )

            # ── STEP 5: Upload encrypted bytes to S3 ───────
            # Only encrypted bytes go to S3 — never raw bytes
            # s3_key = "encrypted/{data_type}/{filename}"
            s3_key = upload_encrypted_file(encrypted_bytes, filename, data_type)

            # ── STEP 6: Collect result ─────────────────────
            result = {
                "filename"    : filename,
                "data_type"   : data_type,
                "hash1"       : hash1,
                "block_index" : block_index,
                "s3_key"      : s3_key,
                "file_size"   : len(encrypted_bytes)
            }
            results.append(result)

            print(f"  [{i:3d}/{total}]  {filename[:30]:30s} | "
                  f"block={block_index} | "
                  f"hash1={hash1[:16]}... | "
                  f"{len(encrypted_bytes)}B → S3")

        except Exception as e:
            print(f"  [{i:3d}/{total}]  {filename} — ERROR: {e}")
            continue

    print(f"  {'─'*50}")
    print(f"  [pipeline] Done — {len(results)}/{total} files processed successfully\n")

    return results


# ─────────────────────────────────────────────
# CONVENIENCE WRAPPERS — one per data type
# These call the right preprocessor then run_pipeline()
# ─────────────────────────────────────────────

def run_text_pipeline(csv_path: str, limit: int = None) -> list:
    """
    Full pipeline for text data.
    csv_path: path to ham_only.csv or spam_ham_mixed.csv
    """
    print(f"  [text] Preprocessing: {csv_path}")
    records = preprocess_text(csv_path)
    print(f"  [text] {len(records)} records loaded")
    return run_pipeline(records, data_type="text", limit=limit)


def run_image_pipeline(folder_path: str, limit: int = None) -> list:
    """
    Full pipeline for image data.
    folder_path: path to datasets/image/baseline/ or mixed/
    """
    print(f"  [image] Preprocessing: {folder_path}")
    records = preprocess_image(folder_path)
    print(f"  [image] {len(records)} images loaded")
    return run_pipeline(records, data_type="image", limit=limit)


def run_audio_pipeline(folder_path: str, limit: int = None) -> list:
    """
    Full pipeline for audio data.
    folder_path: path to datasets/audio/baseline/ or mixed/
    """
    print(f"  [audio] Preprocessing: {folder_path}")
    records = preprocess_audio(folder_path)
    print(f"  [audio] {len(records)} audio files loaded")
    return run_pipeline(records, data_type="audio", limit=limit)
