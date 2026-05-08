"""
run_phase4.py — OBHSB Phase 4 Full Pipeline
=============================================
Runs the complete Phase 4 pipeline:
  Part A — DoS Attack Simulation (5 files per data type = 15 total)
  Part B — Performance Metrics measurement
  Part C — Comparison table + charts + CSV

Run from project root:
  python run_phase4.py

Outputs:
  outputs/metrics_charts.png
  outputs/comparison_table.csv
  outputs/phase4_summary.txt
"""

import os
import time
from datetime import datetime

from dos_simulation import inject_attack, run_dos_audit, restore_file
from metrics import (
    load_samples,
    measure_encryption_time,
    measure_decryption_time,
    measure_hash_time,
    measure_throughput,
    measure_resource_usage,
    measure_stability,
    compute_confidential_rate,
)
from comparison import (
    generate_comparison_table,
    plot_charts,
    save_comparison_csv,
    OUTPUT_DIR,
)

DIVIDER = "=" * 60


def run_dos_simulation():
    """
    Part A — DoS attack on 5 files per data type (15 total).
    Files are picked dynamically from S3 — no hardcoded filenames.
    inject → audit → restore for each file.
    """
    print(f"\n{DIVIDER}")
    print("  PART A — DoS Attack Simulation (15 files)")
    print(DIVIDER)

    from modules.s3_handler import list_files

    dos_files = []

    # Pick 5 files per data type directly from S3 — guaranteed to exist
    for data_type in ["text", "audio", "image"]:
        s3_keys   = list_files(prefix=f"encrypted/{data_type}/")
        filenames = [k.split("/")[-1] for k in s3_keys if k.split("/")[-1] != ""][:5]
        for fname in filenames:
            dos_files.append({"filename": fname, "data_type": data_type})
        print(f"  [DOS] {data_type}: picked {len(filenames)} files from S3")

    dos_results = []

    for tf in dos_files:
        filename  = tf["filename"]
        data_type = tf["data_type"]

        print(f"\n  ── Attacking: {filename} [{data_type}] ──")

        inject_attack(filename, data_type)
        audit   = run_dos_audit(filename, data_type)
        restore_file(filename, data_type)

        dos_results.append({
            "filename"     : filename,
            "data_type"    : data_type,
            "attack_caught": audit["attack_caught"],
            "verdict"      : audit["verdict"],
            "hash1"        : audit["hash1"],
            "hash2"        : audit["hash2"],
        })

    caught = sum(1 for r in dos_results if r["attack_caught"])
    print(f"\n  [DOS] DoS simulation complete — {caught}/{len(dos_results)} attacks caught")
    return dos_results


def run_metrics():
    """
    Part B — Measure all performance metrics.
    """
    print(f"\n{DIVIDER}")
    print("  PART B — Performance Metrics")
    print(DIVIDER)

    samples      = load_samples(sample_size=10)
    enc          = measure_encryption_time(samples)
    dec          = measure_decryption_time(samples)
    hash_m       = measure_hash_time(samples)
    throughput   = measure_throughput(samples)
    resource     = measure_resource_usage(samples)
    stability    = measure_stability("ham_0005.txt", "text", trials=50)
    confidential = compute_confidential_rate()

    return {
        "enc"         : enc,
        "dec"         : dec,
        "hash"        : hash_m,
        "throughput"  : throughput,
        "resource"    : resource,
        "stability"   : stability,
        "confidential": confidential,
    }


def run_comparison(metrics):
    """
    Part C — Generate comparison table, charts, CSV.
    """
    print(f"\n{DIVIDER}")
    print("  PART C — Comparison Table + Charts")
    print(DIVIDER)

    table      = generate_comparison_table(
        enc_metrics          = metrics["enc"],
        dec_metrics          = metrics["dec"],
        throughput_metrics   = metrics["throughput"],
        resource_metrics     = metrics["resource"],
        stability_metrics    = metrics["stability"],
        confidential_metrics = metrics["confidential"],
    )
    chart_path = plot_charts(table)
    csv_path   = save_comparison_csv(table)

    return table, chart_path, csv_path


def save_summary(dos_results, metrics, table, chart_path, csv_path):
    """
    Save a plain text summary of Phase 4 results.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    summary_path = os.path.join(OUTPUT_DIR, "phase4_summary.txt")

    caught       = sum(1 for r in dos_results if r["attack_caught"])
    total        = len(dos_results)
    by_type      = {}
    for r in dos_results:
        dt = r["data_type"]
        if dt not in by_type:
            by_type[dt] = {"caught": 0, "total": 0}
        by_type[dt]["total"] += 1
        if r["attack_caught"]:
            by_type[dt]["caught"] += 1

    with open(summary_path, "w") as f:
        f.write("OBHSB Phase 4 — Summary Report\n")
        f.write(f"Generated : {datetime.now().isoformat(timespec='seconds')}\n")
        f.write("=" * 60 + "\n\n")

        # Part A
        f.write("PART A — DoS Simulation Results\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Total files attacked : {total}\n")
        f.write(f"  Total attacks caught : {caught}/{total}\n")
        f.write(f"  Detection rate       : {round(caught/total*100, 1)} %\n\n")
        f.write(f"  {'Type':<8} {'Caught':>8} {'Total':>7}\n")
        f.write(f"  {'-'*8} {'-'*8} {'-'*7}\n")
        for dt, v in by_type.items():
            f.write(f"  {dt:<8} {v['caught']:>8} {v['total']:>7}\n")
        f.write("\n  Per-file results:\n")
        for r in dos_results:
            status = " CAUGHT" if r["attack_caught"] else " MISSED"
            f.write(f"    {r['filename']:<40} {status}\n")
        f.write("\n")

        # Part B
        f.write("PART B — OBHSB Performance Metrics\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Avg Encryption Time  : {metrics['enc']['avg_ms']} ms\n")
        f.write(f"  Avg Decryption Time  : {metrics['dec']['avg_ms']} ms\n")
        f.write(f"  Avg Hash Time        : {metrics['hash']['avg_ms']} ms\n")
        f.write(f"  Avg Throughput       : {metrics['throughput']['avg_mbps']} Mbps\n")
        f.write(f"  Avg CPU Usage        : {metrics['resource']['avg_cpu_percent']} %\n")
        f.write(f"  Avg Memory Usage     : {metrics['resource']['avg_memory_mb']} MB\n")
        f.write(f"  Stability            : {metrics['stability']['stability_pct']} % ({metrics['stability']['successes']}/{metrics['stability']['trials']} trials)\n")
        f.write(f"  Confidential Rate    : {metrics['confidential']['confidential_rate']} %\n\n")
        f.write("  NOTE: Enc/Dec time and throughput reflect hardware AES-NI\n")
        f.write("  acceleration — faster than paper's software-based environment.\n\n")

        # Part C
        f.write("PART C — Comparison Table (Paper Table 3)\n")
        f.write("-" * 40 + "\n")
        f.write(f"  {'Method':<40} {'Enc ms':>8} {'Dec ms':>8} {'Mbps':>7} {'Conf%':>7} {'Stab%':>7}\n")
        f.write(f"  {'-'*40} {'-'*8} {'-'*8} {'-'*7} {'-'*7} {'-'*7}\n")
        for row in table:
            f.write(
                f"  {row['method']:<40} "
                f"{row['avg_enc_time_ms']:>8} "
                f"{row['avg_dec_time_ms']:>8} "
                f"{row['avg_throughput_mbps']:>7} "
                f"{row['confidential_rate']:>7} "
                f"{row['stability_pct']:>7}\n"
            )
        f.write("\n")

        # Output files
        f.write("OUTPUT FILES\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Chart   : {chart_path}\n")
        f.write(f"  CSV     : {csv_path}\n")
        f.write(f"  Summary : {summary_path}\n")

    print(f"\n  [PHASE4]  Summary saved → {summary_path}")
    return summary_path


def main():
    start_time = time.time()

    print(f"\n{'='*60}")
    print("  OBHSB — Phase 4: DoS Simulation + Performance Metrics")
    print(f"  Started: {datetime.now().isoformat(timespec='seconds')}")
    print(f"{'='*60}")

    dos_results              = run_dos_simulation()
    metrics                  = run_metrics()
    table, chart_path, csv_path = run_comparison(metrics)
    summary_path             = save_summary(dos_results, metrics, table, chart_path, csv_path)

    elapsed = round(time.time() - start_time, 1)
    caught  = sum(1 for r in dos_results if r["attack_caught"])

    print(f"\n{DIVIDER}")
    print("  PHASE 4 COMPLETE ")
    print(DIVIDER)
    print(f"  Total time     : {elapsed}s")
    print(f"  Chart          : {chart_path}")
    print(f"  CSV            : {csv_path}")
    print(f"  Summary        : {summary_path}")
    print(f"  DoS caught     : {caught}/{len(dos_results)}")
    print(f"  Stability      : {metrics['stability']['stability_pct']} %")
    print(f"  Conf. Rate     : {metrics['confidential']['confidential_rate']} %")
    print(f"  Enc time avg   : {metrics['enc']['avg_ms']} ms")
    print(f"  Dec time avg   : {metrics['dec']['avg_ms']} ms")
    print(f"  Throughput avg : {metrics['throughput']['avg_mbps']} Mbps")
    print(DIVIDER)


if __name__ == "__main__":
    main()
