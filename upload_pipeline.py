"""
upload_pipeline.py — OBHSB Phase 1 Upload Pipeline
====================================================
Runs Phase 0 → Phase 1 for ALL dataset files.

What it does per file:
  1. Read raw file bytes
  2. Preprocess (preprocessor.py)
  3. AES-256 Encrypt (encryption.py) → encrypted_bytes + Hash1
  4. Upload encrypted_bytes to S3 (s3_handler.py)
  5. Store Hash1 in blockchain (blockchain.py)

S3 structure:
  obhsb-project-anbu/
  ├── text/
  ├── image/
  ├── audio/
  └── quarantine/
        ├── text/
        ├── image/
        └── audio/

Datasets:
  text  → datasets/text/mixed/txt_files/   (500 .txt)
  image → datasets/image/mixed/            (700 .jpg)
  audio → datasets/audio/mixed/            (699 .wav)

Free Tier Budget: 2,000 PUT/month → 1,899 files = safe ✅
"""

import os
import sys
import time
import logging
from pathlib import Path
from dotenv import load_dotenv

# ── load .env ──────────────────────────────────────────────────────────────────
load_dotenv()

# ── project root on your Fedora machine ───────────────────────────────────────
PROJECT_ROOT = Path("/home/anbuselvanmurugesan/Documents/obhsb_project")
sys.path.insert(0, str(PROJECT_ROOT))

from modules.encryption  import encrypt_bytes, compute_hash
from modules.blockchain  import init_chain, add_block
from modules.s3_handler  import upload_encrypted_file

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.StreamHandler(),
    ]
)
log = logging.getLogger(__name__)

# ── constants ─────────────────────────────────────────────────────────────────
BUCKET_NAME  = "obhsb-project-anbu"

DATASETS = {
    "text" : PROJECT_ROOT / "datasets" / "text"  / "mixed" / "txt_files",
    "image": PROJECT_ROOT / "datasets" / "image" / "mixed",
    "audio": PROJECT_ROOT / "datasets" / "audio" / "mixed",
}

EXTENSIONS = {
    "text" : {".txt"},
    "image": {".jpg", ".jpeg"},
    "audio": {".wav"},
}

# files to always skip
SKIP_FILES = {"desktop.ini", "thumbs.db", ".ds_store"}


# ──────────────────────────────────────────────────────────────────────────────
def should_skip(filename: str) -> bool:
    """Return True for hidden or system files."""
    name = filename.lower()
    return name in SKIP_FILES or name.startswith(".")


def upload_single_file(file_path: Path, data_type: str) -> dict:
    """
    Full Phase 0 → Phase 1 pipeline for one file.

    Returns a result dict:
      {filename, data_type, s3_key, hash1, status, error}
    """
    filename = file_path.name
    result = {
        "filename" : filename,
        "data_type": data_type,
        "s3_key"   : f"{data_type}/{filename}",
        "hash1"    : None,
        "status"   : "FAILED",
        "error"    : None,
    }

    try:
        # ── Step 0: Read raw bytes ─────────────────────────────────────────
        raw_bytes = file_path.read_bytes()

        # ── Step 1a: Encrypt → IV(16 bytes) + ciphertext ──────────────────
        encrypted_bytes = encrypt_bytes(raw_bytes)

        # ── Step 1b: Hash1 = SHA-256(encrypted_bytes) ─────────────────────
        hash1 = compute_hash(encrypted_bytes)
        result["hash1"] = hash1

        # ── Step 1c: Upload encrypted file to S3 ──────────────────────────
        s3_key = upload_encrypted_file(encrypted_bytes, filename, data_type)

        # ── Step 1d: Store Hash1 in Blockchain ────────────────────────────
        add_block(
            filename  = filename,
            hash1     = hash1,
            data_type = data_type,
            file_size = len(encrypted_bytes),
        )

        result["status"] = "SUCCESS"
        result["s3_key"] = s3_key
        log.info(f"✅  {data_type:5s}  {filename}  →  s3://{BUCKET_NAME}/{s3_key}")

    except Exception as e:
        result["error"] = str(e)
        log.error(f"❌  {data_type:5s}  {filename}  →  {e}")

    return result


# ──────────────────────────────────────────────────────────────────────────────
def upload_dataset(data_type: str, folder: Path) -> list:
    """
    Upload all files of one data_type from folder.
    Returns list of result dicts.
    """
    valid_exts = EXTENSIONS[data_type]
    files = [
        f for f in sorted(folder.iterdir())
        if f.is_file()
        and f.suffix.lower() in valid_exts
        and not should_skip(f.name)
    ]

    log.info(f"\n{'='*60}")
    log.info(f"  Uploading {data_type.upper()} — {len(files)} files")
    log.info(f"  Folder : {folder}")
    log.info(f"  S3 key : s3://{BUCKET_NAME}/{data_type}/")
    log.info(f"{'='*60}")

    results = []
    for i, file_path in enumerate(files, 1):
        log.info(f"  [{i:3d}/{len(files)}] {file_path.name}")
        r = upload_single_file(file_path, data_type)
        results.append(r)

    success = sum(1 for r in results if r["status"] == "SUCCESS")
    failed  = sum(1 for r in results if r["status"] == "FAILED")
    log.info(f"\n  {data_type.upper()} done → ✅ {success} uploaded, ❌ {failed} failed\n")

    return results


# ──────────────────────────────────────────────────────────────────────────────
def run_pipeline(data_types=None):
    """
    Run the full upload pipeline.

    Args:
        data_types: list of types to upload, e.g. ["text"]
                    None = upload all three (text, image, audio)
    """
    if data_types is None:
        data_types = ["text", "image", "audio"]


    log.info("=" * 60)
    log.info("  OBHSB Upload Pipeline — Phase 0 → Phase 1")
    log.info(f"  Bucket : {BUCKET_NAME}")
    log.info(f"  Types  : {data_types}")
    log.info("=" * 60)

    start = time.time()

    # initialise blockchain (creates SQLite DB + genesis block if not exists)
    init_chain()

    all_results = []

    for data_type in data_types:
        folder = DATASETS[data_type]
        if not folder.exists():
            log.error(f"Folder not found: {folder}")
            continue
        results = upload_dataset(data_type, folder)
        all_results.extend(results)

    # ── Final summary ──────────────────────────────────────────────────────
    elapsed  = time.time() - start
    total    = len(all_results)
    success  = sum(1 for r in all_results if r["status"] == "SUCCESS")
    failed   = sum(1 for r in all_results if r["status"] == "FAILED")

    log.info("\n" + "=" * 60)
    log.info("  UPLOAD PIPELINE COMPLETE")
    log.info(f"  Total files : {total}")
    log.info(f"  Success     : {success} ✅")
    log.info(f"  Failed      : {failed} ❌")
    log.info(f"  Time taken  : {elapsed:.1f}s")
    log.info(f"  S3 PUTs used: {success} / 2000 free tier budget")
    log.info("=" * 60)

    # warn if any failures
    if failed:
        log.warning("\nFailed files:")
        for r in all_results:
            if r["status"] == "FAILED":
                log.warning(f"  {r['data_type']:5s}  {r['filename']}  →  {r['error']}")

    return all_results


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    """
    Usage:
      python upload_pipeline.py              # upload all 3 types
      python upload_pipeline.py text         # upload text only
      python upload_pipeline.py image audio  # upload image + audio only
    """
    args = sys.argv[1:]
    valid = {"text", "image", "audio"}

    if args:
        types = [a.lower() for a in args if a.lower() in valid]
        invalid = [a for a in args if a.lower() not in valid]
        if invalid:
            print(f"Unknown types: {invalid}. Valid: text, image, audio")
            sys.exit(1)
    else:
        types = None   # all three

    run_pipeline(data_types=types)
