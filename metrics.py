import time
import os
import psutil
import numpy as np
from modules.encryption import encrypt_bytes, decrypt_bytes, compute_hash
from modules.preprocessor import preprocess_image, preprocess_audio
from modules.auditing import audit_file
from dos_simulation import inject_attack, run_dos_audit, restore_file

# Dataset paths
DATASET_BASE = "/home/anbuselvanmurugesan/Documents/obhsb_project/datasets"

DATASET_PATHS = {
    "text" : f"{DATASET_BASE}/text/mixed/txt_files",
    "image": f"{DATASET_BASE}/image/mixed",
    "audio": f"{DATASET_BASE}/audio/mixed",
}

SAMPLE_SIZE = 10  # files per data type


def load_samples(sample_size=SAMPLE_SIZE):
    """
    Load raw bytes from local dataset — no S3 needed.
    Returns list of dicts: {filename, data, data_type}

    NOTE: Audio files (~132KB) and padded text (~35KB) are used for
    timing measurements. Raw text files (32-48 bytes) are too small
    for meaningful encryption time / throughput measurement.
    This matches the paper's implied ~35KB file size for metrics.
    """
    samples = []

    # Audio — 132KB each, closest to paper's benchmark file size
    aud_records = preprocess_audio(DATASET_PATHS["audio"])[:sample_size]
    for r in aud_records:
        samples.append({"filename": r["filename"], "data": r["data"], "data_type": "audio"})

    # Image — ~9KB each
    img_records = preprocess_image(DATASET_PATHS["image"])[:sample_size]
    for r in img_records:
        samples.append({"filename": r["filename"], "data": r["data"], "data_type": "image"})

    # Text — pad small text files to ~35KB to match paper benchmark
    # Raw text is 32-48 bytes — too small for meaningful timing
    txt_folder = DATASET_PATHS["text"]
    txt_files  = [f for f in os.listdir(txt_folder) if f.endswith(".txt")][:sample_size]
    TARGET_SIZE = 35 * 1024  # 35KB
    for fname in txt_files:
        with open(os.path.join(txt_folder, fname), "rb") as f:
            raw = f.read()
        # Repeat content to reach target size
        padded = (raw * (TARGET_SIZE // len(raw) + 1))[:TARGET_SIZE]
        samples.append({"filename": fname, "data": padded, "data_type": "text"})

    print(f"  [METRICS] Loaded {len(samples)} samples ({sample_size} per type)")
    print(f"  [METRICS] Avg sample size: {np.mean([len(s['data']) for s in samples]):.0f} bytes")
    return samples


def measure_encryption_time(samples):
    """
    Step 4 — Measure AES-256 encryption time across all samples.
    """
    print(f"\n  [METRICS]   Measuring encryption time ({len(samples)} files)...")

    times = []
    for s in samples:
        start = time.perf_counter()
        encrypt_bytes(s["data"])
        end = time.perf_counter()
        times.append((end - start) * 1000)

    result = {
        "avg_ms" : round(np.mean(times), 4),
        "min_ms" : round(np.min(times), 4),
        "max_ms" : round(np.max(times), 4),
        "count"  : len(times),
        "times"  : [round(t, 4) for t in times],
    }

    print(f"  [METRICS]     Avg : {result['avg_ms']} ms")
    print(f"  [METRICS]     Min : {result['min_ms']} ms")
    print(f"  [METRICS]     Max : {result['max_ms']} ms")
    return result


def measure_decryption_time(samples):
    """
    Step 5 — Measure AES-256 decryption time.
    Pre-encrypts each sample first, then times only decryption.
    """
    print(f"\n  [METRICS]   Measuring decryption time ({len(samples)} files)...")

    encrypted_samples = [
        {"filename": s["filename"], "data_type": s["data_type"], "encrypted": encrypt_bytes(s["data"])}
        for s in samples
    ]

    times = []
    for s in encrypted_samples:
        start = time.perf_counter()
        decrypt_bytes(s["encrypted"])
        end = time.perf_counter()
        times.append((end - start) * 1000)

    result = {
        "avg_ms" : round(np.mean(times), 4),
        "min_ms" : round(np.min(times), 4),
        "max_ms" : round(np.max(times), 4),
        "count"  : len(times),
        "times"  : [round(t, 4) for t in times],
    }

    print(f"  [METRICS]     Avg : {result['avg_ms']} ms")
    print(f"  [METRICS]     Min : {result['min_ms']} ms")
    print(f"  [METRICS]     Max : {result['max_ms']} ms")
    return result


def measure_hash_time(samples):
    """
    Step 6 — Measure SHA-256 hash computation time on encrypted bytes.
    """
    print(f"\n  [METRICS]   Measuring hash computation time ({len(samples)} files)...")

    encrypted_samples = [
        {"filename": s["filename"], "data_type": s["data_type"], "encrypted": encrypt_bytes(s["data"])}
        for s in samples
    ]

    times = []
    for s in encrypted_samples:
        start = time.perf_counter()
        compute_hash(s["encrypted"])
        end = time.perf_counter()
        times.append((end - start) * 1000)

    result = {
        "avg_ms" : round(np.mean(times), 4),
        "min_ms" : round(np.min(times), 4),
        "max_ms" : round(np.max(times), 4),
        "count"  : len(times),
        "times"  : [round(t, 4) for t in times],
    }

    print(f"  [METRICS]     Avg : {result['avg_ms']} ms")
    print(f"  [METRICS]     Min : {result['min_ms']} ms")
    print(f"  [METRICS]     Max : {result['max_ms']} ms")
    return result


def measure_throughput(samples):
    """
    Step 7 — Measure encryption throughput in Mbps.
    Formula: (bytes * 8) / (seconds * 1_000_000)
    """
    print(f"\n  [METRICS]  Measuring throughput ({len(samples)} files)...")

    mbps_list = []
    for s in samples:
        byte_count = len(s["data"])
        start = time.perf_counter()
        encrypt_bytes(s["data"])
        end = time.perf_counter()
        elapsed_sec = end - start
        if elapsed_sec == 0:
            continue
        mbps_list.append((byte_count * 8) / (elapsed_sec * 1_000_000))

    result = {
        "avg_mbps" : round(np.mean(mbps_list), 4),
        "min_mbps" : round(np.min(mbps_list), 4),
        "max_mbps" : round(np.max(mbps_list), 4),
        "count"    : len(mbps_list),
        "mbps_list": [round(m, 4) for m in mbps_list],
    }

    print(f"  [METRICS]     Avg : {result['avg_mbps']} Mbps")
    print(f"  [METRICS]     Min : {result['min_mbps']} Mbps")
    print(f"  [METRICS]     Max : {result['max_mbps']} Mbps")
    return result


def measure_resource_usage(samples):
    """
    Step 8 — Measure CPU and memory usage during encryption.
    Equation (8): R*u = Pr × Δt

    Uses cpu_percent(interval=0.1) — blocks for 100ms and returns
    a real CPU reading. interval=None always returns 0.0 for fast
    operations because AES encryption finishes before psutil can sample.
    """
    print(f"\n  [METRICS]  Measuring resource usage ({len(samples)} files)...")

    process = psutil.Process(os.getpid())

    cpu_readings    = []
    memory_readings = []

    for s in samples:
        mem_before = process.memory_info().rss / (1024 * 1024)

        # Reset CPU counter first
        process.cpu_percent(interval=None)
        # Run encryption
        encrypt_bytes(s["data"])
        # interval=0.1 blocks 100ms — gives accurate CPU% over that window
        cpu = process.cpu_percent(interval=0.1)

        mem_after = process.memory_info().rss / (1024 * 1024)
        cpu_readings.append(cpu)
        memory_readings.append(max(mem_before, mem_after))

    result = {
        "avg_cpu_percent"  : round(float(np.mean(cpu_readings)), 4),
        "peak_cpu_percent" : round(float(np.max(cpu_readings)), 4),
        "avg_memory_mb"    : round(float(np.mean(memory_readings)), 4),
        "peak_memory_mb"   : round(float(np.max(memory_readings)), 4),
        "count"            : len(samples),
    }

    print(f"  [METRICS]     Avg CPU  : {result['avg_cpu_percent']} %")
    print(f"  [METRICS]     Peak CPU : {result['peak_cpu_percent']} %")
    print(f"  [METRICS]     Avg Mem  : {result['avg_memory_mb']} MB")
    print(f"  [METRICS]     Peak Mem : {result['peak_memory_mb']} MB")
    return result


def measure_stability(filename, data_type, trials=10):
    """
    Step 9 — Measure system stability by running audit N times.
    Stability % = (successful audits / total trials) * 100
    """
    print(f"\n  [METRICS]  Measuring stability ({trials} trials on {filename})...")

    successes = 0
    failures  = 0

    for i in range(trials):
        try:
            result = audit_file(filename, data_type)
            if result["verdict"] == "FILE ACCESSED":
                successes += 1
            else:
                failures += 1
                print(f"  [METRICS]     Trial {i+1} FAILED — verdict: {result['verdict']}")
        except Exception as e:
            failures += 1
            print(f"  [METRICS]     Trial {i+1} ERROR — {e}")

    stability_pct = round((successes / trials) * 100, 2)

    result = {
        "filename"     : filename,
        "data_type"    : data_type,
        "trials"       : trials,
        "successes"    : successes,
        "failures"     : failures,
        "stability_pct": stability_pct,
    }

    print(f"  [METRICS]     Successes : {successes}/{trials}")
    print(f"  [METRICS]     Stability : {stability_pct} %")
    return result


def compute_confidential_rate():
    """
    Step 10 — Measure confidential rate.
    Injects attacks on one file per data type, verifies all caught.
    Confidential rate = (detected / total_tampered) * 100
    """
    print(f"\n  [METRICS]  Measuring confidential rate...")

    # dog0005.wav confirmed in S3 — dog0001.wav deleted during Phase 3 testing
    test_files = [
        {"filename": "ham_0001.txt", "data_type": "text"},
        {"filename": "dog0005.wav",  "data_type": "audio"},
    ]

    img_folder = DATASET_PATHS["image"]
    img_files  = [f for f in os.listdir(img_folder) if f.lower().endswith(".jpg")]
    if img_files:
        test_files.append({"filename": img_files[0], "data_type": "image"})

    details  = []
    detected = 0

    for tf in test_files:
        filename  = tf["filename"]
        data_type = tf["data_type"]

        print(f"\n  [METRICS]   Testing: {filename} [{data_type}]")

        inject_attack(filename, data_type)
        audit_result = run_dos_audit(filename, data_type)
        restore_file(filename, data_type)

        caught = audit_result["attack_caught"]
        if caught:
            detected += 1

        details.append({
            "filename"     : filename,
            "data_type"    : data_type,
            "attack_caught": caught,
            "verdict"      : audit_result["verdict"],
        })

    total             = len(test_files)
    confidential_rate = round((detected / total) * 100, 2)

    result = {
        "total_tampered"   : total,
        "detected"         : detected,
        "missed"           : total - detected,
        "confidential_rate": confidential_rate,
        "details"          : details,
    }

    print(f"\n  [METRICS]     Total tampered : {total}")
    print(f"  [METRICS]     Detected       : {detected}")
    print(f"  [METRICS]     Missed         : {total - detected}")
    print(f"  [METRICS]     Confidential   : {confidential_rate} %")
    return result
