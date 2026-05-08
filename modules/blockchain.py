import sqlite3
import hashlib
import json
import time
import os

# ─────────────────────────────────────────────
# blockchain.db lives in the project root folder
# obhsb_project/blockchain.db
# ─────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "blockchain.db")


# ─────────────────────────────────────────────
# HELPER — Compute block_hash
# SHA-256(index + timestamp + data_json + previous_hash)
# This ties every block to its parent — tamper any field → hash breaks
# ─────────────────────────────────────────────
def _compute_block_hash(block_index: int, timestamp: float, data: dict, previous_hash: str) -> str:
    raw = str(block_index) + str(timestamp) + json.dumps(data, sort_keys=True) + previous_hash
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


# ─────────────────────────────────────────────
# STEP 1 — init_chain()
# Creates the SQLite table if it doesn't exist
# Creates Genesis Block (Block 0) if chain is empty
# Safe to call multiple times — won't duplicate genesis
# ─────────────────────────────────────────────
def init_chain():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Create table — ONLY INSERT ever (no UPDATE, no DELETE)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            block_index   INTEGER PRIMARY KEY,
            timestamp     REAL    NOT NULL,
            data          TEXT    NOT NULL,
            previous_hash TEXT    NOT NULL,
            block_hash    TEXT    NOT NULL
        )
    """)
    conn.commit()

    # Check if genesis block already exists
    cur.execute("SELECT COUNT(*) FROM blocks")
    count = cur.fetchone()[0]

    if count == 0:
        # Create Genesis Block (Block 0)
        timestamp     = time.time()
        data          = {"info": "OBHSB Genesis Block", "filename": None, "hash1": None,
                         "data_type": None, "file_size": None}
        previous_hash = "0" * 64   # no parent exists

        block_hash = _compute_block_hash(0, timestamp, data, previous_hash)

        cur.execute(
            "INSERT INTO blocks VALUES (?, ?, ?, ?, ?)",
            (0, timestamp, json.dumps(data, sort_keys=True), previous_hash, block_hash)
        )
        conn.commit()
        print(f"  [blockchain] Genesis block created → block_hash: {block_hash[:20]}...")

    conn.close()


# ─────────────────────────────────────────────
# STEP 2 — add_block()
# Appends a new block with Hash1 for one uploaded file
# Returns the new block_index
# Called AFTER encrypt_bytes() and before s3 upload
# ─────────────────────────────────────────────
def add_block(filename: str, hash1: str, data_type: str, file_size: int) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Get last block to chain from
    cur.execute("SELECT block_index, block_hash FROM blocks ORDER BY block_index DESC LIMIT 1")
    last = cur.fetchone()

    new_index     = last[0] + 1
    previous_hash = last[1]
    timestamp     = time.time()

    data = {
        "filename"  : filename,
        "hash1"     : hash1,        # SHA-256 of ENCRYPTED bytes — the fingerprint
        "data_type" : data_type,    # "text" / "image" / "audio"
        "file_size" : file_size     # size of encrypted bytes
    }

    block_hash = _compute_block_hash(new_index, timestamp, data, previous_hash)

    # ONLY INSERT — never UPDATE or DELETE
    cur.execute(
        "INSERT INTO blocks VALUES (?, ?, ?, ?, ?)",
        (new_index, timestamp, json.dumps(data, sort_keys=True), previous_hash, block_hash)
    )
    conn.commit()
    conn.close()

    print(f"  [blockchain] Block {new_index} added → {filename} | hash1: {hash1[:20]}...")
    return new_index


# ─────────────────────────────────────────────
# STEP 3 — get_hash1()
# Fetches the stored Hash1 for a given filename
# Used in Phase 3 (key matching): compare Hash1 vs Hash2
# ─────────────────────────────────────────────
def get_hash1(filename: str) -> str | None:
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    cur.execute("SELECT data FROM blocks WHERE data LIKE ?", (f'%"{filename}"%',))
    rows = cur.fetchall()
    conn.close()

    for row in rows:
        data = json.loads(row[0])
        if data.get("filename") == filename and data.get("hash1"):
            return data["hash1"]

    return None   # filename not found in chain


# ─────────────────────────────────────────────
# STEP 4 — get_chain()
# Returns all blocks as a list of dicts
# Used for viewing the blockchain in Flask dashboard
# ─────────────────────────────────────────────
def get_chain() -> list:
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    cur.execute("SELECT block_index, timestamp, data, previous_hash, block_hash FROM blocks ORDER BY block_index ASC")
    rows = cur.fetchall()
    conn.close()

    chain = []
    for row in rows:
        chain.append({
            "block_index"   : row[0],
            "timestamp"     : row[1],
            "data"          : json.loads(row[2]),
            "previous_hash" : row[3],
            "block_hash"    : row[4]
        })
    return chain


# ─────────────────────────────────────────────
# STEP 5 — verify_chain()
# Re-computes every block_hash and checks:
#   1. block_hash matches recomputed hash
#   2. previous_hash links correctly to prior block
# Returns True if chain is intact, False if tampered
# ─────────────────────────────────────────────
def verify_chain() -> bool:
    chain = get_chain()

    for i, block in enumerate(chain):
        # Re-compute expected block_hash
        expected_hash = _compute_block_hash(
            block["block_index"],
            block["timestamp"],
            block["data"],
            block["previous_hash"]
        )

        # Check 1: block_hash integrity
        if block["block_hash"] != expected_hash:
            print(f"  Block {i} TAMPERED — block_hash mismatch!")
            return False

        # Check 2: chain link (skip genesis)
        if i > 0:
            expected_prev = chain[i - 1]["block_hash"]
            if block["previous_hash"] != expected_prev:
                print(f"   Block {i} BROKEN LINK — previous_hash mismatch!")
                return False

    print(f"   Chain intact — {len(chain)} blocks verified")
    return True
