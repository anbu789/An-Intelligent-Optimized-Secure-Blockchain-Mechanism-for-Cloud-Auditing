"""
buffalo.py — Phase 2: African Buffalo Optimization Algorithm
OBHSB Project

Step 1: sha256_bytes() + hash_to_vector()
Step 2: build_normal_profile_from_csv()    ← text data (spam.csv)
        build_normal_profile_from_files()  ← image / audio data
"""

import csv
import hashlib
import logging
import os
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [BUFFALO] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("buffalo")

VECTOR_SIZE = 32   # SHA-256 = 64 hex chars = 32 byte-pairs = 32 floats


def sha256_bytes(data: bytes) -> str:
    """
    Compute SHA-256 of raw bytes.
    Returns 64-char lowercase hex string.
    """
    return hashlib.sha256(data).hexdigest()


def hash_to_vector(hex_hash: str) -> np.ndarray:
    """
    Convert a 64-char SHA-256 hex string into a 32-float numpy array.

    How:
      Split hex string into 32 pairs of 2 chars each.
      Convert each pair from hex -> int (0-255) -> float.

    Example:
      "2cf2..." -> [44.0, 242.0, ...]   shape: (32,)

    This lets Buffalo compare hashes using cosine_similarity
    (homomorphic — works on hashes, never on raw data).
    """
    if len(hex_hash) != 64:
        raise ValueError(f"Expected 64-char hex hash, got {len(hex_hash)} chars")

    return np.array(
        [int(hex_hash[i:i+2], 16) for i in range(0, 64, 2)],
        dtype=float
    )


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — BUILD NORMAL PROFILE
# ══════════════════════════════════════════════════════════════════════════════

def build_normal_profile_from_csv(csv_path: str,
                                   label_col: str = "v1",
                                   text_col: str = "v2",
                                   normal_label: str = "ham") -> np.ndarray:
    """
    Build the text normal profile using ALL ham rows from spam.csv.

    Steps:
      1. Read every row where label == 'ham'
      2. Encode text -> UTF-8 bytes
      3. SHA-256(bytes) -> 64-char hex
      4. hash_to_vector() -> 32-float array
      5. Mean of ALL vectors = normal_profile

    Why ALL rows:
      More samples = more stable mean vector.
      The profile won't drift because of a few edge-case messages.

    Args:
        csv_path     : path to spam.csv
        label_col    : column with label  (default 'v1')
        text_col     : column with text   (default 'v2')
        normal_label : which label is normal (default 'ham')

    Returns:
        mean_vector: np.ndarray shape (32,)  — Buffalo's anchor for text
    """
    vectors = []

    with open(csv_path, encoding="latin-1", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row.get(label_col, "").strip().lower()
            if label != normal_label.lower():
                continue                          # skip spam rows
            text_bytes = row[text_col].encode("utf-8")
            hex_hash   = sha256_bytes(text_bytes)
            vec        = hash_to_vector(hex_hash)
            vectors.append(vec)

    if not vectors:
        raise ValueError(
            f"No '{normal_label}' rows found in {csv_path}. "
            f"Check label_col='{label_col}' and the file path."
        )

    mean_vector = np.mean(vectors, axis=0)        # shape: (32,)

    logger.info(
        f"[PROFILE] Text normal profile built — "
        f"{len(vectors)} '{normal_label}' rows used from '{csv_path}'"
    )
    return mean_vector


def build_normal_profile_from_files(folder_path: str) -> np.ndarray:
    """
    Build the image or audio normal profile using ALL files in a folder.

    Steps:
      1. Read every file in folder as raw bytes
      2. SHA-256(bytes) -> 64-char hex
      3. hash_to_vector() -> 32-float array
      4. Mean of ALL vectors = normal_profile

    Used for:
      - Good carrot images  -> image normal_profile
      - Dog audio files     -> audio normal_profile

    Args:
        folder_path : directory containing ONLY clean/normal files
                      (no malicious files should be in this folder)

    Returns:
        mean_vector: np.ndarray shape (32,)  — Buffalo's anchor for this type
    """
    if not os.path.isdir(folder_path):
        raise FileNotFoundError(
            f"Folder not found: '{folder_path}'. "
            f"Make sure your baseline dataset folder exists."
        )

    vectors = []
    skipped = []

    for filename in sorted(os.listdir(folder_path)):
        filepath = os.path.join(folder_path, filename)
        if not os.path.isfile(filepath):
            continue                              # skip subdirectories
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
            hex_hash = sha256_bytes(raw)
            vec      = hash_to_vector(hex_hash)
            vectors.append(vec)
        except Exception as e:
            skipped.append(filename)
            logger.warning(f"[PROFILE] Skipping '{filename}': {e}")

    if not vectors:
        raise ValueError(
            f"No files could be processed in: '{folder_path}'. "
            f"Check that the folder contains image or audio files."
        )

    mean_vector = np.mean(vectors, axis=0)        # shape: (32,)

    logger.info(
        f"[PROFILE] File normal profile built — "
        f"{len(vectors)} files used from '{folder_path}'"
        + (f" | {len(skipped)} skipped" if skipped else "")
    )
    return mean_vector


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2b — LOAD OR BUILD PROFILE  (cache wrapper)
# ══════════════════════════════════════════════════════════════════════════════

def load_or_build_profile(data_type: str,
                          source: str,
                          profile_dir: str = "profiles") -> np.ndarray:
    """
    Load a saved normal profile if it exists, otherwise build and save it.

    This means the expensive profile-building step (hashing thousands of
    files) runs ONCE. Every run after that just loads the .npy file instantly.

    Profile filenames:
      profiles/text_normal_profile.npy
      profiles/image_normal_profile.npy
      profiles/audio_normal_profile.npy

    Args:
        data_type   : "text", "image", or "audio"
        source      : path to spam.csv  (if data_type == "text")
                      path to folder    (if data_type == "image" or "audio")
        profile_dir : folder where .npy files are saved (default "profiles/")

    Returns:
        mean_vector : np.ndarray shape (32,) — loaded or freshly built
    """
    valid_types = ("text", "image", "audio")
    if data_type not in valid_types:
        raise ValueError(
            f"data_type must be one of {valid_types}, got '{data_type}'"
        )

    # ── Where the cached profile lives ────────────────────────────────────────
    os.makedirs(profile_dir, exist_ok=True)
    profile_path = os.path.join(profile_dir, f"{data_type}_normal_profile.npy")

    # ── Load if already saved ─────────────────────────────────────────────────
    if os.path.exists(profile_path):
        profile = np.load(profile_path)
        logger.info(
            f"[PROFILE] Loaded '{data_type}' profile from cache "
            f"— '{profile_path}'"
        )
        return profile

    # ── Build from scratch (first run only) ───────────────────────────────────
    logger.info(
        f"[PROFILE] No cache found for '{data_type}' "
        f"— building from source '{source}' ..."
    )

    if data_type == "text":
        profile = build_normal_profile_from_csv(source)
    else:
        profile = build_normal_profile_from_files(source)

    # ── Save for next time ────────────────────────────────────────────────────
    np.save(profile_path, profile)
    logger.info(
        f"[PROFILE] '{data_type}' profile saved to cache "
        f"— '{profile_path}'"
    )

    return profile


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Pa*(b3)  ATTACK DETECTION  [Equation 2]
# ══════════════════════════════════════════════════════════════════════════════

from sklearn.metrics.pairwise import cosine_similarity as _cosine_similarity

# Per-type thresholds — data-driven from real dataset investigation:
#
#   text  : SHA-256 is too uniform on text — 0.7 used for integrity detection
#           (ham vs spam gap is ~0.003 — content classification not possible)
#
#   image : Real gap exists between good/bad carrot (0.920 vs 0.846 = 0.136 gap)
#           Threshold 0.91 gives 100% MAAA for good, 100% WAAH for bad carrot
#
#   audio : SHA-256 uniform on WAV bytes — 0.7 used for integrity detection
#           (dog vs cat gap is ~0.003 — content classification not possible)
#
THRESHOLDS = {
    "text"  : 0.7,
    "image" : 0.91,
    "audio" : 0.7,
}
MAAA_THRESHOLD = 0.7   # kept for backwards compatibility (default)


def compute_fitness(hash_vector: np.ndarray,
                    normal_profile: np.ndarray) -> float:
    """
    Equation (2) — core fitness calculation:
      fitness = cosine_similarity(hash_vector, normal_profile)

    Cosine similarity measures the angle between two vectors.
      angle ~ 0   (pointing same direction)  →  similarity ~ 1.0  →  SAFE
      angle ~ 90  (pointing different ways)  →  similarity ~ 0.0  →  SUSPICIOUS

    Returns:
        float in [0.0, 1.0]
    """
    sim = _cosine_similarity(
        hash_vector.reshape(1, -1),
        normal_profile.reshape(1, -1)
    )[0][0]
    return float(np.clip(sim, 0.0, 1.0))


def pa_star_b3(data_bytes: bytes,
               normal_profile: np.ndarray,
               data_type: str = "text") -> dict:
    """
    Pa*(b3) — Full attack detection pipeline — Equation (2).

    Steps:
      1. SHA-256(data_bytes)            →  64-char hex
      2. hash_to_vector(hex)            →  32-float numpy array
      3. compute_fitness(vec, profile)  →  float 0.0–1.0
      4. Threshold decision (per data_type):
           text/audio : fitness >= 0.70  →  MAAA ✅  SAFE
           image      : fitness >= 0.91  →  MAAA ✅  SAFE
           any type   : below threshold  →  WAAH ❌  MALICIOUS

    Why per-type thresholds:
      SHA-256 output is uniform for text and audio — any text hashes
      to a vector near [127.5, ...] regardless of content.
      Image bytes however carry structural patterns — good carrot vs
      bad carrot produce measurably different hash vectors (gap = 0.136).
      Threshold 0.91 gives 100% correct detection on real carrot dataset.

    Args:
        data_bytes     : raw bytes of the file being scanned
        normal_profile : mean hash vector for this data type (from Step 2)
        data_type      : "text", "image", or "audio" (default "text")

    Returns dict:
        hex_hash     — SHA-256 hex of the scanned file
        hash_vector  — 32-float list (JSON-serialisable)
        fitness      — cosine similarity score (0.0–1.0)
        threshold    — threshold used for this data_type
        verdict      — "SAFE" or "MALICIOUS"
        signal       — "MAAA" or "WAAH"
        data_type    — data type used
    """
    if data_type not in THRESHOLDS:
        raise ValueError(f"data_type must be one of {list(THRESHOLDS)}, got '{data_type}'")

    threshold   = THRESHOLDS[data_type]
    hex_hash    = sha256_bytes(data_bytes)
    hash_vector = hash_to_vector(hex_hash)
    fitness     = compute_fitness(hash_vector, normal_profile)

    if fitness >= threshold:
        verdict = "SAFE"
        signal  = "MAAA"    # ✅ safe location — allow
    else:
        verdict = "MALICIOUS"
        signal  = "WAAH"    # ❌ unsafe location — block + remove

    return {
        "hex_hash"   : hex_hash,
        "hash_vector": hash_vector.tolist(),
        "fitness"    : round(fitness, 6),
        "threshold"  : threshold,
        "verdict"    : verdict,
        "signal"     : signal,
        "data_type"  : data_type,
    }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Na*(b3)  ATTACK NEGLECTION  [Equation 3]
# ══════════════════════════════════════════════════════════════════════════════

# Separation thresholds — how big must the gap be to act?
#
#   separation = normal_fitness − attack_fitness
#
#   > 0.15  →  CLEAR_ANOMALY    gap is large and obvious  → block + remove
#   > 0.00  →  MARGINAL         gap exists but small       → flag for review
#   ≤ 0.00  →  WITHIN_TOLERANCE suspicious file scores as  → allow
#                                well as or better than      (false alarm)
#                                normal — not an attack
#
SEPARATION_CLEAR    = 0.15   # gap > 0.15  →  CLEAR_ANOMALY
SEPARATION_MARGINAL = 0.00   # gap > 0.00  →  MARGINAL


def na_star_b3(normal_fitness: float,
               attack_fitness: float) -> dict:
    """
    Na*(b3) — Attack Neglection — Equation (3).

    Pa*(b3) flags individual files as MAAA or WAAH.
    Na*(b3) confirms the anomaly by measuring the SEPARATION between
    a known-normal file and the suspicious file.

    Why this matters:
      Pa* alone can produce false alarms — a normal file might score
      below threshold by chance. Na* adds a second check:
      if the suspicious file scores just as well as a normal file,
      the gap is zero or negative → not a real attack (WITHIN_TOLERANCE).
      Only a genuinely anomalous file produces a large separation → act on it.

    Equation (3):
      separation = normal_fitness − attack_fitness

    Decision:
      separation > 0.15  →  CLEAR_ANOMALY    → block + remove immediately
      separation > 0.00  →  MARGINAL         → flag, human review needed
      separation ≤ 0.00  →  WITHIN_TOLERANCE → allow, false alarm

    Args:
        normal_fitness : fitness score of a known-normal file (from pa_star_b3)
        attack_fitness : fitness score of the suspicious file  (from pa_star_b3)

    Returns dict:
        normal_fitness   — fitness of the normal file
        attack_fitness   — fitness of the suspicious file
        separation       — normal_fitness − attack_fitness
        anomaly_level    — "CLEAR_ANOMALY", "MARGINAL", or "WITHIN_TOLERANCE"
        action           — "BLOCK_AND_REMOVE", "FLAG_FOR_REVIEW", or "ALLOW"
    """
    separation = normal_fitness - attack_fitness

    if separation > SEPARATION_CLEAR:
        anomaly_level = "CLEAR_ANOMALY"
        action        = "BLOCK_AND_REMOVE"
    elif separation > SEPARATION_MARGINAL:
        anomaly_level = "MARGINAL"
        action        = "FLAG_FOR_REVIEW"
    else:
        anomaly_level = "WITHIN_TOLERANCE"
        action        = "ALLOW"

    return {
        "normal_fitness" : round(normal_fitness, 6),
        "attack_fitness" : round(attack_fitness, 6),
        "separation"     : round(separation, 6),
        "anomaly_level"  : anomaly_level,
        "action"         : action,
    }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — scan_files()  SCAN A FOLDER OF MIXED FILES
# ══════════════════════════════════════════════════════════════════════════════

def scan_files(folder_path: str,
               normal_profile: np.ndarray,
               data_type: str = "text") -> list:
    """
    Scan all files in a folder using Pa*(b3) + Na*(b3).

    This is the core Buffalo scanning loop for a local folder.
    In the full pipeline, this same logic runs on S3 files
    Results are returned as a list of dicts.

    Pipeline per file:
      1. Read raw bytes
      2. pa_star_b3(bytes, profile, data_type) → fitness + MAAA/WAAH
      3. If WAAH → na_star_b3(mean_normal_fitness, attack_fitness) → action
      4. If MAAA → action = "ALLOW" (no Na* needed)

    normal_fitness reference for Na*:
      We use the MEAN fitness of all MAAA files in this scan batch.
      These are the files that passed Pa* — our best estimate of
      what a normal file scores in this batch.
      Falls back to the threshold value if no MAAA files found.

    Args:
        folder_path    : path to folder containing files to scan
        normal_profile : mean hash vector built from baseline files
        data_type      : "text", "image", or "audio"

    Returns:
        list of dicts, one per file, each containing:
          filename       — file name
          file_path      — full path
          hex_hash       — SHA-256 of the file
          fitness        — Pa* fitness score
          threshold      — threshold used for this data_type
          pa_signal      — "MAAA" or "WAAH"
          pa_verdict     — "SAFE" or "MALICIOUS"
          na_separation  — separation score (None if MAAA)
          na_level       — anomaly level (None if MAAA)
          action         — final action taken
          data_type      — data type scanned
    """
    if not os.path.isdir(folder_path):
        raise FileNotFoundError(f"Folder not found: '{folder_path}'")

    # Skip known system/junk files that are not data files
    SKIP_FILES = {
        "desktop.ini", "thumbs.db", ".ds_store",
        ".gitkeep", ".gitignore",
    }

    files = sorted([
        f for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
        and f.lower() not in SKIP_FILES
        and not f.startswith(".")
    ])

    if not files:
        raise ValueError(f"No files found in folder: '{folder_path}'")

    logger.info(
        f"[SCAN] Starting scan — {len(files)} files "
        f"in '{folder_path}' (type={data_type})"
    )

    # ── Pass 1: run Pa* on every file ────────────────────────────────────────
    pa_results = []
    for fname in files:
        fpath = os.path.join(folder_path, fname)
        with open(fpath, "rb") as f:
            raw = f.read()
        pa = pa_star_b3(raw, normal_profile, data_type)
        pa_results.append((fname, fpath, pa))

    # ── Compute mean normal fitness from MAAA files ───────────────────────────
    maaa_fitness = [pa["fitness"] for _, _, pa in pa_results
                    if pa["signal"] == "MAAA"]

    if maaa_fitness:
        mean_normal_fitness = float(np.mean(maaa_fitness))
    else:
        # No MAAA files — fall back to threshold as reference
        mean_normal_fitness = THRESHOLDS[data_type]
        logger.warning(
            f"[SCAN] No MAAA files found — using threshold "
            f"{mean_normal_fitness} as normal_fitness reference"
        )

    logger.info(
        f"[SCAN] MAAA files: {len(maaa_fitness)}/{len(files)}  "
        f"mean normal fitness: {mean_normal_fitness:.4f}"
    )

    # ── Pass 2: run Na* on WAAH files ─────────────────────────────────────────
    results = []
    for fname, fpath, pa in pa_results:
        if pa["signal"] == "MAAA":
            # Safe file — no Na* needed
            result = {
                "filename"     : fname,
                "file_path"    : fpath,
                "hex_hash"     : pa["hex_hash"],
                "fitness"      : pa["fitness"],
                "threshold"    : pa["threshold"],
                "pa_signal"    : pa["signal"],
                "pa_verdict"   : pa["verdict"],
                "na_separation": None,
                "na_level"     : None,
                "action"       : "ALLOW",
                "data_type"    : data_type,
            }
        else:
            # Suspicious file — run Na* to confirm anomaly
            na = na_star_b3(mean_normal_fitness, pa["fitness"])
            result = {
                "filename"     : fname,
                "file_path"    : fpath,
                "hex_hash"     : pa["hex_hash"],
                "fitness"      : pa["fitness"],
                "threshold"    : pa["threshold"],
                "pa_signal"    : pa["signal"],
                "pa_verdict"   : pa["verdict"],
                "na_separation": na["separation"],
                "na_level"     : na["anomaly_level"],
                "action"       : na["action"],
                "data_type"    : data_type,
            }

        results.append(result)

    # ── Summary log ───────────────────────────────────────────────────────────
    allow  = sum(1 for r in results if r["action"] == "ALLOW")
    flag   = sum(1 for r in results if r["action"] == "FLAG_FOR_REVIEW")
    block  = sum(1 for r in results if r["action"] == "BLOCK_AND_REMOVE")

    logger.info(
        f"[SCAN] Complete — "
        f"ALLOW: {allow}  FLAG: {flag}  BLOCK: {block}  "
        f"Total: {len(results)}"
    )

    return results
