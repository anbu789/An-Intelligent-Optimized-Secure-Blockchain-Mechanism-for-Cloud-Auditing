"""
pipeline_phase2.py — OBHSB Phase 2 Pipeline (Paper-correct order)
==================================================================
Implements the paper's flowchart exactly:

  Initialize dataset
        ↓
  Buffalo scan (Pa* + Na*) on RAW bytes
        ↓
  Malicious? YES → BLOCK (never uploaded to S3)
  Malicious? NO  → Encrypt → Upload S3 → Store blockchain

This matches Fig. 4 of the paper:
  "Proposed model → Malicious events → YES: Remove malicious nodes
                                      → NO:  Cloud storage"

Buffalo runs on RAW bytes (pre-encryption) so it can actually
detect content differences — image works perfectly, text/audio
are integrity-based.

Usage:
  python pipeline_phase2.py              # scan + upload all 3 types
  python pipeline_phase2.py image        # image only
  python pipeline_phase2.py text audio   # text + audio only

  # Dry run (scan only, no S3 upload):
  python pipeline_phase2.py --dry-run
"""

import os
import sys
import time
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path("/home/anbuselvanmurugesan/Documents/obhsb_project")
sys.path.insert(0, str(PROJECT_ROOT))

from modules.buffalo     import (pa_star_b3, na_star_b3,
                                 load_or_build_profile,
                                 build_normal_profile_from_csv,
                                 THRESHOLDS)
from modules.encryption  import encrypt_bytes, compute_hash
from modules.blockchain  import init_chain, add_block
from modules.s3_handler  import upload_encrypted_file
import numpy as np

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(message)s",
    handlers= [logging.StreamHandler()],
)
log = logging.getLogger(__name__)

# ── constants ─────────────────────────────────────────────────────────────────
BUCKET_NAME  = "obhsb-project-anbu"
PROFILES_DIR = PROJECT_ROOT / "profiles"

DATASETS = {
    "text" : PROJECT_ROOT / "datasets" / "text"  / "mixed" / "txt_files",
    "image": PROJECT_ROOT / "datasets" / "image" / "mixed",
    "audio": PROJECT_ROOT / "datasets" / "audio" / "mixed",
}

BASELINES = {
    "text" : PROJECT_ROOT / "datasets" / "text"  / "baseline" / "ham_only.csv",
    "image": PROJECT_ROOT / "datasets" / "image" / "baseline",
    "audio": PROJECT_ROOT / "datasets" / "audio" / "baseline",
}

EXTENSIONS = {
    "text" : {".txt"},
    "image": {".jpg", ".jpeg"},
    "audio": {".wav"},
}

SKIP_FILES = {"desktop.ini", "thumbs.db", ".ds_store"}

SEPARATOR = "=" * 60


# ── Profile loading ───────────────────────────────────────────────────────────

def get_profile(data_type: str) -> np.ndarray:
    """
    Load or build the normal profile for a data type.
    Uses raw baseline files (pre-encryption) — correct for Phase 2.
    """
    os.makedirs(PROFILES_DIR, exist_ok=True)

    if data_type == "text":
        return load_or_build_profile(
            data_type   = "text",
            source      = str(BASELINES["text"]),
            profile_dir = str(PROFILES_DIR),
        )
    else:
        return load_or_build_profile(
            data_type   = data_type,
            source      = str(BASELINES[data_type]),
            profile_dir = str(PROFILES_DIR),
        )


# ── Single file pipeline ──────────────────────────────────────────────────────

def process_single_file(file_path: Path,
                        data_type: str,
                        profile: np.ndarray,
                        mean_normal_fitness: float,
                        dry_run: bool = False) -> dict:
    """
    Full pipeline for one file:
      1. Read raw bytes
      2. Pa*(b3) — Buffalo attack detection on raw bytes
      3. Na*(b3) — anomaly level if WAAH
      4. If MAAA  → encrypt → upload S3 → store blockchain
      5. If WAAH  → block (never uploaded)

    Returns result dict.
    """
    filename = file_path.name
    result = {
        "filename"      : filename,
        "data_type"     : data_type,
        "pa_signal"     : None,
        "pa_fitness"    : None,
        "na_separation" : None,
        "na_level"      : None,
        "action"        : None,
        "s3_key"        : None,
        "hash1"         : None,
        "status"        : "FAILED",
        "error"         : None,
    }

    try:
        # ── Step 1: Read raw bytes ─────────────────────────────────────────
        raw_bytes = file_path.read_bytes()

        # ── Step 2: Pa*(b3) — Buffalo scan on raw bytes ────────────────────
        pa = pa_star_b3(raw_bytes, profile, data_type)
        result["pa_signal"]  = pa["signal"]
        result["pa_fitness"] = pa["fitness"]

        if pa["signal"] == "WAAH":
            # ── Step 3: Na*(b3) — confirm anomaly level ───────────────────
            na = na_star_b3(mean_normal_fitness, pa["fitness"])
            result["na_separation"] = na["separation"]
            result["na_level"]      = na["anomaly_level"]
            result["action"]        = na["action"]

            # BLOCK — do not encrypt, do not upload
            result["status"] = "BLOCKED"
            log.warning(
                f"  {data_type:5s}  {filename:<45}  "
                f"fitness={pa['fitness']:.4f}  "
                f"sep={na['separation']:.4f}  "
                f"→ {na['action']}"
            )

        else:
            # ── MAAA — safe file ───────────────────────────────────────────
            result["action"] = "ALLOW"

            if not dry_run:
                # ── Step 4a: Encrypt ──────────────────────────────────────
                encrypted_bytes = encrypt_bytes(raw_bytes)

                # ── Step 4b: Hash1 = SHA-256(encrypted bytes) ─────────────
                hash1 = compute_hash(encrypted_bytes)
                result["hash1"] = hash1

                # ── Step 4c: Upload to S3 ─────────────────────────────────
                s3_key = upload_encrypted_file(encrypted_bytes, filename, data_type)
                result["s3_key"] = s3_key

                # ── Step 4d: Store in blockchain ──────────────────────────
                add_block(
                    filename  = filename,
                    hash1     = hash1,
                    data_type = data_type,
                    file_size = len(encrypted_bytes),
                )

            result["status"] = "UPLOADED" if not dry_run else "WOULD_UPLOAD"
            log.info(
                f"  {data_type:5s}  {filename:<45}  "
                f"fitness={pa['fitness']:.4f}  "
                f"→ {'uploaded' if not dry_run else 'would upload'}"
            )

    except Exception as e:
        result["error"] = str(e)
        log.error(f"  {data_type:5s}  {filename}  →  ERROR: {e}")

    return result


# ── Dataset pipeline ──────────────────────────────────────────────────────────

def process_dataset(data_type: str,
                    folder: Path,
                    profile: np.ndarray,
                    dry_run: bool = False) -> list:
    """
    Process all files of one data type:
      Pass 1 — Pa* on all files to get MAAA scores
      Compute mean_normal_fitness from MAAA files
      Pass 2 — Na* on WAAH files using mean_normal_fitness
    """
    valid_exts = EXTENSIONS[data_type]
    files = [
        f for f in sorted(folder.iterdir())
        if f.is_file()
        and f.suffix.lower() in valid_exts
        and f.name.lower() not in SKIP_FILES
        and not f.name.startswith(".")
    ]

    if not files:
        log.error(f"No files found in {folder}")
        return []

    log.info(f"\n{SEPARATOR}")
    log.info(f"  {data_type.upper()} — {len(files)} files")
    log.info(f"  Folder    : {folder}")
    log.info(f"  Threshold : {THRESHOLDS[data_type]}")
    log.info(f"  Mode      : {'DRY RUN' if dry_run else 'LIVE'}")
    log.info(SEPARATOR)

    # ── Pass 1: Pa* on every file to get fitness scores ───────────────────
    log.info("  Pass 1 — Running Pa*(b3) on all files...")
    pa_results = []
    for file_path in files:
        raw = file_path.read_bytes()
        pa  = pa_star_b3(raw, profile, data_type)
        pa_results.append((file_path, pa))

    # ── Compute mean normal fitness from MAAA files ───────────────────────
    maaa_scores = [pa["fitness"] for _, pa in pa_results if pa["signal"] == "MAAA"]
    if maaa_scores:
        mean_normal_fitness = float(np.mean(maaa_scores))
    else:
        mean_normal_fitness = THRESHOLDS[data_type]
        log.warning(f"  No MAAA files found — using threshold as reference")

    maaa_count = len(maaa_scores)
    waah_count = len(files) - maaa_count
    log.info(f"  MAAA (safe)    : {maaa_count}/{len(files)}")
    log.info(f"  WAAH (suspect) : {waah_count}/{len(files)}")
    log.info(f"  Mean normal fitness : {mean_normal_fitness:.4f}")

    # ── Pass 2: Full pipeline per file ────────────────────────────────────
    log.info(f"\n  Pass 2 — Processing files (Buffalo → Encrypt → S3)...")
    if not dry_run:
        init_chain()

    results = []
    for file_path, pa in pa_results:
        if pa["signal"] == "MAAA":
            # Safe — encrypt + upload
            result = process_single_file(
                file_path, data_type, profile,
                mean_normal_fitness, dry_run)
        else:
            # WAAH — run Na* and block
            na = na_star_b3(mean_normal_fitness, pa["fitness"])
            filename = file_path.name
            result = {
                "filename"      : filename,
                "data_type"     : data_type,
                "pa_signal"     : "WAAH",
                "pa_fitness"    : pa["fitness"],
                "na_separation" : na["separation"],
                "na_level"      : na["anomaly_level"],
                "action"        : na["action"],
                "s3_key"        : None,
                "hash1"         : None,
                "status"        : "BLOCKED",
                "error"         : None,
            }
            log.warning(
                f"  {data_type:5s}  {filename:<45}  "
                f"fitness={pa['fitness']:.4f}  "
                f"sep={na['separation']:.4f}  "
                f"→ {na['action']}"
            )
        results.append(result)

    # ── Summary ───────────────────────────────────────────────────────────
    uploaded = sum(1 for r in results if r["status"] in ("UPLOADED", "WOULD_UPLOAD"))
    blocked  = sum(1 for r in results if r["status"] == "BLOCKED")
    failed   = sum(1 for r in results if r["status"] == "FAILED")

    log.info(f"\n  {data_type.upper()} COMPLETE")
    log.info(f"   Uploaded (safe)  : {uploaded}")
    log.info(f"   Blocked (WAAH)   : {blocked}")
    log.info(f"   Failed (error)   : {failed}")

    # Show all blocked files
    blocked_results = [r for r in results if r["status"] == "BLOCKED"]
    if blocked_results:
        log.info(f"\n  BLOCKED files ({len(blocked_results)} total):")
        for r in blocked_results:
            log.info(
                f"    {r['filename']:<45}  "
                f"fitness={r['pa_fitness']:.4f}  "
                f"sep={r['na_separation']:.4f}  "
                f"level={r['na_level']}  "
                f"action={r['action']}"
            )

    return results


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(data_types=None, dry_run=False):
    """
    Run Phase 2 pipeline for all data types.

    Args:
        data_types : list of types, e.g. ["image"] — None = all three
        dry_run    : if True, scan only, no S3 upload
    """
    if data_types is None:
        data_types = ["text", "image", "audio"]

    log.info(f"\n{SEPARATOR}")
    log.info("  OBHSB Phase 2 Pipeline — Buffalo → Encrypt → S3")
    log.info(f"  Bucket   : {BUCKET_NAME}")
    log.info(f"  Types    : {data_types}")
    log.info(f"  Mode     : {'DRY RUN (no S3 uploads)' if dry_run else 'LIVE'}")
    log.info(SEPARATOR)

    start       = time.time()
    all_results = []

    for data_type in data_types:
        folder = DATASETS[data_type]
        if not folder.exists():
            log.error(f"Folder not found: {folder}")
            continue

        # Load profile from raw baseline files
        log.info(f"\n  Loading {data_type} profile from baseline...")
        profile = get_profile(data_type)

        results = process_dataset(data_type, folder, profile, dry_run)
        all_results.extend(results)

    # ── Overall summary ───────────────────────────────────────────────────
    elapsed  = time.time() - start
    total    = len(all_results)
    uploaded = sum(1 for r in all_results if r["status"] in ("UPLOADED", "WOULD_UPLOAD"))
    blocked  = sum(1 for r in all_results if r["status"] == "BLOCKED")
    failed   = sum(1 for r in all_results if r["status"] == "FAILED")

    # Count by action type
    flag_block = sum(1 for r in all_results if r["action"] == "FLAG_FOR_REVIEW")
    hard_block = sum(1 for r in all_results if r["action"] == "BLOCK_AND_REMOVE")

    log.info(f"\n{SEPARATOR}")
    log.info("  PHASE 2 PIPELINE COMPLETE")
    log.info(SEPARATOR)
    log.info(f"  Total files scanned  : {total}")
    log.info(f"   Safe  (uploaded)  : {uploaded}")
    log.info(f"   Blocked (WAAH)    : {blocked}")
    log.info(f"     └ FLAG_FOR_REVIEW : {flag_block}")
    log.info(f"     └ BLOCK_AND_REMOVE: {hard_block}")
    log.info(f"   Failed (error)    : {failed}")
    log.info(f"  Time taken           : {elapsed:.1f}s")
    if not dry_run:
        log.info(f"  S3 PUTs used         : {uploaded} / 2000 free tier budget")
    log.info(SEPARATOR)

    return all_results


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args     = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry_run  = "--dry-run" in sys.argv
    valid    = {"text", "image", "audio"}

    if args:
        types = [a.lower() for a in args if a.lower() in valid]
        invalid = [a for a in args if a.lower() not in valid]
        if invalid:
            print(f"Unknown types: {invalid}. Valid: text, image, audio")
            sys.exit(1)
    else:
        types = None

    run_pipeline(data_types=types, dry_run=dry_run)
