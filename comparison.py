"""
comparison.py — OBHSB Phase 4 Comparison Table
================================================
Compares paper-reported OBHSB values vs our measured OBHSB values.
Only 2 rows: Paper (Expected) vs Ours (Measured).
"""

import csv
import os
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # non-interactive backend — works on Fedora without display issues

# ── Paper Table 3 — OBHSB expected values (from paper) ───────────────────────
PAPER_VALUES = {
    "method"             : "OBHSB (Paper)",
    "resource_usage_pct" : 7.5,
    "stability_pct"      : 99.0,
    "avg_enc_time_ms"    : 3.5,
    "avg_dec_time_ms"    : 4.2,
    "avg_throughput_mbps": 95.0,
    "confidential_rate"  : 100.0,
}

OUTPUT_DIR = "/home/anbuselvanmurugesan/Documents/obhsb_project/outputs"


def generate_comparison_table(
    enc_metrics,
    dec_metrics,
    throughput_metrics,
    resource_metrics,
    stability_metrics,
    confidential_metrics,
):
    """
    Build comparison table — Paper values vs our measured values.

    Args:
        enc_metrics          : result from measure_encryption_time()
        dec_metrics          : result from measure_decryption_time()
        throughput_metrics   : result from measure_throughput()
        resource_metrics     : result from measure_resource_usage()
        stability_metrics    : result from measure_stability()
        confidential_metrics : result from compute_confidential_rate()

    Returns:
        list of 2 dicts — [paper_row, ours_row]
    """
    print(f"\n  [COMPARE] Generating comparison table (Paper vs Ours)...")

    # Our measured row
    ours_row = {
        "method"             : "OBHSB (Ours)",
        "resource_usage_pct" : resource_metrics["avg_cpu_percent"],
        "stability_pct"      : stability_metrics["stability_pct"],
        "avg_enc_time_ms"    : enc_metrics["avg_ms"],
        "avg_dec_time_ms"    : dec_metrics["avg_ms"],
        "avg_throughput_mbps": throughput_metrics["avg_mbps"],
        "confidential_rate"  : confidential_metrics["confidential_rate"],
    }

    table = [PAPER_VALUES, ours_row]

    # Print to console
    print(f"\n  {'Method':<22} {'Res%':>6} {'Stab%':>7} {'Enc ms':>8} {'Dec ms':>8} {'Mbps':>10} {'Conf%':>7}")
    print(f"  {'-'*22} {'-'*6} {'-'*7} {'-'*8} {'-'*8} {'-'*10} {'-'*7}")
    for row in table:
        print(
            f"  {row['method']:<22} "
            f"{row['resource_usage_pct']:>6} "
            f"{row['stability_pct']:>7} "
            f"{row['avg_enc_time_ms']:>8} "
            f"{row['avg_dec_time_ms']:>8} "
            f"{row['avg_throughput_mbps']:>10} "
            f"{row['confidential_rate']:>7}"
        )

    return table


def plot_charts(table):
    """
    Generate side-by-side bar charts — Paper vs Ours, 6 metrics.
    Paper bar = blue, Ours bar = green.
    Saves to outputs/metrics_charts.png.

    Args:
        table : list of 2 dicts from generate_comparison_table()

    Returns:
        str — path to saved PNG
    """
    print(f"\n  [COMPARE] Generating charts (Paper vs Ours)...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "metrics_charts.png")

    labels = ["Paper", "Ours"]
    colors = ["#4a90d9", "#27ae60"]  # blue for paper, green for ours

    metrics = [
        {"key": "avg_enc_time_ms",     "title": "Avg Encryption Time (ms)",  "lower_is_better": True},
        {"key": "avg_dec_time_ms",     "title": "Avg Decryption Time (ms)",  "lower_is_better": True},
        {"key": "avg_throughput_mbps", "title": "Avg Throughput (Mbps)",     "lower_is_better": False},
        {"key": "confidential_rate",   "title": "Confidential Rate (%)",     "lower_is_better": False},
        {"key": "resource_usage_pct",  "title": "Resource Usage (%)",        "lower_is_better": True},
        {"key": "stability_pct",       "title": "Stability (%)",             "lower_is_better": False},
    ]

    fig, axes = plt.subplots(2, 3, figsize=(14, 8))
    fig.suptitle(
        "OBHSB — Paper vs Measured Results",
        fontsize=14, fontweight="bold", y=1.02
    )

    for i, metric in enumerate(metrics):
        ax     = axes[i // 3][i % 3]
        values = [row[metric["key"]] for row in table]

        bars = ax.bar(labels, values, color=colors, edgecolor="white",
                      linewidth=0.8, width=0.4)

        # Value labels on top of each bar
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(values) * 0.02,
                str(round(val, 2)),
                ha="center", va="bottom",
                fontsize=10, fontweight="bold"
            )

        ax.set_title(metric["title"], fontsize=11, fontweight="bold", pad=8)
        ax.set_ylim(0, max(values) * 1.25)
        ax.grid(axis="y", linestyle="--", alpha=0.4)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        note = "↓ lower is better" if metric["lower_is_better"] else "↑ higher is better"
        ax.text(
            0.98, 0.97, note,
            transform=ax.transAxes,
            ha="right", va="top",
            fontsize=8, color="grey", style="italic"
        )

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor="#4a90d9", label="OBHSB (Paper — Expected)"),
        Patch(facecolor="#27ae60", label="OBHSB (Ours — Measured)"),
    ]
    fig.legend(
        handles=legend_elements,
        loc="lower center",
        ncol=2,
        fontsize=10,
        frameon=False,
        bbox_to_anchor=(0.5, -0.03)
    )

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"  [COMPARE] Chart saved → {output_path}")
    return output_path


def save_comparison_csv(table):
    """
    Save comparison table (Paper vs Ours) to CSV.
    Saves to outputs/comparison_table.csv.

    Args:
        table : list of 2 dicts from generate_comparison_table()

    Returns:
        str — path to saved CSV
    """
    print(f"\n  [COMPARE] Saving comparison table to CSV...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "comparison_table.csv")

    fieldnames = [
        "method",
        "avg_enc_time_ms",
        "avg_dec_time_ms",
        "avg_throughput_mbps",
        "confidential_rate",
        "resource_usage_pct",
        "stability_pct",
    ]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in table:
            writer.writerow({k: row[k] for k in fieldnames})

    print(f"  [COMPARE] CSV saved → {output_path}")
    return output_path
