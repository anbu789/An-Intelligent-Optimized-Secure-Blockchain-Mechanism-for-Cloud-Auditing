"""
app.py — OBHSB Phase 5 Flask Dashboard
=======================================
Routes:
  GET  /              → Home (upload form + recent audit logs)
  POST /upload        → Process uploaded file through Phase 0→1 pipeline
  GET  /blockchain    → Blockchain explorer
  GET  /files         → S3 file browser
  POST /audit         → Trigger audit_file() on a selected S3 file
  GET  /buffalo       → Buffalo scan panel
  POST /buffalo/scan  → Run Pa* on a selected file
  GET  /metrics       → Phase 4 comparison table + chart
  GET  /dos           → DoS simulation panel
  POST /dos/inject    → inject_attack()
  POST /dos/audit     → run_dos_audit()
  POST /dos/restore   → restore_file()
"""

import csv
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

# ── Module imports (app.py lives in project root — imports work as-is) ────────
from modules.blockchain import get_chain, verify_chain, init_chain, add_block
from modules.encryption import encrypt_bytes, compute_hash
from modules.s3_handler  import list_files, upload_encrypted_file
from modules.auditing    import audit_file, load_normal_profile
from modules.buffalo     import pa_star_b3, na_star_b3
from dos_simulation      import inject_attack, run_dos_audit, restore_file

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)          # session encryption key

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT  = Path(__file__).parent
OUTPUTS_DIR   = PROJECT_ROOT / "outputs"
AUDIT_LOG_DIR = OUTPUTS_DIR  / "audit_logs"
CHART_PATH    = OUTPUTS_DIR  / "metrics_charts.png"
CSV_PATH      = OUTPUTS_DIR  / "comparison_table.csv"

# Allowed upload extensions (Step 2 rule: txt / jpg / wav only)
ALLOWED_EXT = {".txt", ".jpg", ".wav"}

EXT_TO_TYPE = {
    ".txt": "text",
    ".jpg": "image",
    ".wav": "audio",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXT


def load_recent_audit_logs(n: int = 10) -> list:
    """Return the n most-recent audit log dicts from outputs/audit_logs/."""
    AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    logs = sorted(AUDIT_LOG_DIR.glob("audit_*.json"), key=os.path.getmtime, reverse=True)
    results = []
    for p in logs[:n]:
        try:
            with open(p) as f:
                results.append(json.load(f))
        except Exception:
            pass
    return results


def load_comparison_csv() -> list:
    """Parse outputs/comparison_table.csv → list of row dicts."""
    rows = []
    if CSV_PATH.exists():
        with open(CSV_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(dict(row))
    return rows


def fmt_ts(ts_float) -> str:
    """Format a UNIX timestamp float as a readable datetime string."""
    try:
        return datetime.fromtimestamp(float(ts_float)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts_float)


# ── Initialise blockchain on startup ─────────────────────────────────────────
init_chain()

# ─────────────────────────────────────────────────────────────────────────────
# ROUTE 1 — Home
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    recent_logs = load_recent_audit_logs(10)
    return render_template("index.html", recent_logs=recent_logs)


@app.route("/upload", methods=["POST"])
def upload():
    """
    Phase 0→1 upload pipeline:
      1. Receive uploaded file
      2. Read raw bytes
      3. encrypt_bytes()     → IV + ciphertext
      4. compute_hash()      → Hash1
      5. add_block()         → blockchain
      6. upload_encrypted_file() → S3
    """
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("index"))

    filename = file.filename
    if not allowed_file(filename):
        flash(f"File type not allowed. Use .txt, .jpg, or .wav only.", "danger")
        return redirect(url_for("index"))

    ext       = Path(filename).suffix.lower()
    data_type = EXT_TO_TYPE[ext]

    try:
        raw_bytes       = file.read()
        encrypted_bytes = encrypt_bytes(raw_bytes)
        hash1           = compute_hash(encrypted_bytes)
        block_idx       = add_block(filename, hash1, data_type, len(encrypted_bytes))
        s3_key          = upload_encrypted_file(encrypted_bytes, filename, data_type)

        flash(
            f"✅ '{filename}' uploaded successfully! "
            f"Block #{block_idx} added to blockchain. "
            f"S3 key: {s3_key}",
            "success",
        )
        log.info(f"Upload OK: {filename} → block {block_idx} → {s3_key}")

    except Exception as e:
        flash(f"Upload failed: {e}", "danger")
        log.error(f"Upload error: {e}")

    return redirect(url_for("index"))


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE 2 — Blockchain Explorer
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/blockchain")
def blockchain():
    page     = request.args.get("page", 1, type=int)
    per_page = 50

    chain        = get_chain()
    chain_ok     = verify_chain()
    total_blocks = len(chain)

    # Reverse so newest blocks appear first (skip genesis at index 0 in sort)
    chain_rev = list(reversed(chain))

    total_pages = max(1, (total_blocks + per_page - 1) // per_page)
    page        = max(1, min(page, total_pages))
    start       = (page - 1) * per_page
    end         = start + per_page
    page_blocks = chain_rev[start:end]

    return render_template(
        "blockchain.html",
        blocks      = page_blocks,
        chain_ok    = chain_ok,
        total_blocks= total_blocks,
        page        = page,
        total_pages = total_pages,
        fmt_ts      = fmt_ts,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE 3 — S3 File Browser + Audit Trigger
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/files")
def files():
    tab = request.args.get("tab", "text")

    def get_files(data_type):
        prefix = f"encrypted/{data_type}/"
        try:
            keys = list_files(prefix)
            # Strip the prefix and ignore bare prefix "directory" entries
            return [k.replace(prefix, "") for k in keys if k != prefix and not k.endswith("/")]
        except Exception as e:
            log.error(f"S3 list error ({data_type}): {e}")
            return []

    text_files  = get_files("text")
    image_files = get_files("image")
    audio_files = get_files("audio")

    audit_result = session.pop("audit_result", None)

    return render_template(
        "files.html",
        tab          = tab,
        text_files   = text_files,
        image_files  = image_files,
        audio_files  = audio_files,
        audit_result = audit_result,
    )


@app.route("/audit", methods=["POST"])
def audit():
    filename  = request.form.get("filename", "").strip()
    data_type = request.form.get("data_type", "").strip()

    if not filename or data_type not in ("text", "image", "audio"):
        flash("Invalid audit request.", "danger")
        return redirect(url_for("files"))

    try:
        result = audit_file(filename, data_type)
        session["audit_result"] = result
        log.info(f"Audit done: {filename} → {result['verdict']}")
    except Exception as e:
        flash(f"Audit error: {e}", "danger")
        log.error(f"Audit error: {e}")

    return redirect(url_for("files", tab=data_type))


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE 4 — Buffalo Scan
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/buffalo", methods=["GET"])
def buffalo():
    scan_result = session.pop("buffalo_result", None)
    return render_template("buffalo.html", scan_result=scan_result)


@app.route("/buffalo/scan", methods=["POST"])
def buffalo_scan():
    filename  = request.form.get("filename", "").strip()
    data_type = request.form.get("data_type", "text")

    if not filename or data_type not in ("text", "image", "audio"):
        flash("Please enter a filename and select a data type.", "warning")
        return redirect(url_for("buffalo"))

    try:
        from modules.s3_handler import download_encrypted_file
        encrypted_bytes = download_encrypted_file(filename, data_type)
        normal_profile  = load_normal_profile(data_type)

        # Pa* always uses "text" threshold in audit mode (Key Rule #11)
        pa_result = pa_star_b3(encrypted_bytes, normal_profile, data_type="text")

        # Compute Na* — difference between normal and attack fitness
        normal_fitness = float(normal_profile.mean())
        na_result      = na_star_b3(normal_fitness, pa_result["fitness"])

        session["buffalo_result"] = {
            "filename"      : filename,
            "data_type"     : data_type,
            "fitness"       : round(pa_result["fitness"], 4),
            "threshold"     : pa_result["threshold"],
            "signal"        : pa_result["signal"],
            "normal_fitness": round(normal_fitness, 4),
            "na_neglection" : round(na_result.get("neglection", 0), 4),
        }
        log.info(f"Buffalo scan: {filename} → {pa_result['signal']} (fitness={pa_result['fitness']:.4f})")

    except Exception as e:
        flash(f"Buffalo scan error: {e}", "danger")
        log.error(f"Buffalo scan error: {e}")

    return redirect(url_for("buffalo"))


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE 5 — Metrics Dashboard
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/metrics")
def metrics():
    table = load_comparison_csv()
    chart_exists = CHART_PATH.exists()
    return render_template("metrics.html", table=table, chart_exists=chart_exists)


@app.route("/metrics/chart")
def metrics_chart():
    """Serve the Phase 4 metrics chart PNG."""
    return send_from_directory(str(OUTPUTS_DIR), "metrics_charts.png")


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE 6 — DoS Simulation Panel
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/dos", methods=["GET"])
def dos():
    dos_state = session.get("dos_state", {})
    return render_template("dos.html", dos_state=dos_state)


@app.route("/dos/inject", methods=["POST"])
def dos_inject():
    filename  = request.form.get("filename", "").strip()
    data_type = request.form.get("data_type", "text")

    if not filename or data_type not in ("text", "image", "audio"):
        flash("Please enter a filename and data type.", "warning")
        return redirect(url_for("dos"))

    try:
        result = inject_attack(filename, data_type)
        session["dos_state"] = {
            "filename" : filename,
            "data_type": data_type,
            "inject"   : result,
            "audit"    : None,
            "restore"  : None,
        }
        log.info(f"DoS inject: {filename} → ATTACKED")
    except Exception as e:
        flash(f"Inject error: {e}", "danger")
        log.error(f"DoS inject error: {e}")

    return redirect(url_for("dos"))


@app.route("/dos/audit", methods=["POST"])
def dos_audit():
    dos_state = session.get("dos_state", {})
    filename  = dos_state.get("filename")
    data_type = dos_state.get("data_type")

    if not filename:
        flash("No active DoS session. Inject an attack first.", "warning")
        return redirect(url_for("dos"))

    try:
        result = run_dos_audit(filename, data_type)
        dos_state["audit"] = result
        session["dos_state"] = dos_state
        log.info(f"DoS audit: {filename} → {result['verdict']}")
    except Exception as e:
        flash(f"DoS audit error: {e}", "danger")
        log.error(f"DoS audit error: {e}")

    return redirect(url_for("dos"))


@app.route("/dos/restore", methods=["POST"])
def dos_restore():
    dos_state = session.get("dos_state", {})
    filename  = dos_state.get("filename")
    data_type = dos_state.get("data_type")

    if not filename:
        flash("No active DoS session.", "warning")
        return redirect(url_for("dos"))

    try:
        result = restore_file(filename, data_type)
        dos_state["restore"] = result
        session["dos_state"] = dos_state
        log.info(f"DoS restore: {filename} → {result['status']}")
    except Exception as e:
        flash(f"Restore error: {e}", "danger")
        log.error(f"DoS restore error: {e}")

    return redirect(url_for("dos"))


@app.route("/dos/reset", methods=["POST"])
def dos_reset():
    session.pop("dos_state", None)
    return redirect(url_for("dos"))


# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
