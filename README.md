# OBHSB — Optimized Buffalo-Based Homomorphic SHA Blockchain

A mini project that makes files stored in the cloud **tamper-proof and self-checking**, using encryption, blockchain, and a nature-inspired "smart animal" algorithm to watch over the files 24/7.

> Built as a college mini project by **Anbu Selvan M**, **Adithya B**, and **Raghav S V**, under the guidance of **Raghav RS**.
> Based on the 2024 research paper *"An Intelligent Optimized Secure Blockchain Mechanism for Cloud Auditing"* by Rajeev Kumar and M.P.S. Bhatia (NSUT Delhi), published in *Expert Systems With Applications* (Elsevier).

---

## 1. What problem does this solve? (Plain-English version)

Imagine you upload an important file — a document, a photo, or a voice recording — to a cloud storage service like AWS S3. Two things could go wrong later:

1. **Someone secretly changes or corrupts your file** while it sits in the cloud, and you have no way of knowing.
2. **An attacker tries to sneak in fake or malicious files** disguised as normal ones.

OBHSB solves both problems by combining three ideas:

- **Locking the file** so nobody can read it without the secret key (**encryption**).
- **Writing down a fingerprint of the file in a notebook that can never be erased or edited** (**blockchain**).
- **Having a "guard animal" constantly sniff around the cloud storage**, comparing new files against what "normal" files look like, and kicking out anything suspicious (**the Buffalo algorithm**).

Later, whenever someone wants to open a file, the system re-checks the file's fingerprint against the one written in the permanent notebook. If they match, the file is untouched and safe to open. If they don't match, the system knows the file was tampered with — even if the file still *looks* fine on the surface.

---

## 2. The Big Picture — How Data Flows Through the System

```
 STEP 0                STEP 1                     STEP 2                  STEP 3
┌───────────┐     ┌────────────────┐        ┌──────────────────┐    ┌───────────────────┐
│  Raw File  │ --> │ Encrypt (AES)  │  -->   │ Buffalo watches   │--> │ Someone requests   │
│ (text/img/ │     │ + Hash it +    │        │ the cloud storage │    │ the file back      │
│  audio)    │     │ Save fingerprint│        │ continuously,     │    │ → system re-checks │
│            │     │ in Blockchain  │        │ removing anything  │    │ fingerprint before │
│            │     │ + upload to S3 │        │ that looks off     │    │ unlocking it       │
└───────────┘     └────────────────┘        └──────────────────┘    └───────────────────┘
```

In short: **preprocess → lock it up & fingerprint it → constantly watch it → double-check the fingerprint every time it's opened.**

---

## 3. Meet the "Buffalo Algorithm"

The **African Buffalo Optimization (ABO)** algorithm is inspired by how buffalo herds behave in the wild — they constantly communicate about which areas are safe ("MAAA" call) and which are dangerous ("WAAH" call), and the herd avoids unsafe areas.

In this project, "unsafe areas" are cloud files that look suspicious. Buffalo doesn't read the file's actual content (it never sees your private data) — it only looks at a mathematical "fingerprint" (the SHA-256 hash) of the file, turned into a row of 32 numbers. It compares that fingerprint's pattern to what a "normal" file's fingerprint usually looks like.

- **High similarity to normal → MAAA ✅ (safe, leave it alone)**
- **Low similarity to normal → WAAH ❌ (suspicious, quarantine or remove it)**

This is why the project is called "homomorphic" in spirit — the security check happens on scrambled/hashed data, not the actual private content.

---

## 4. The Three Types of Data Used

To prove the system works generally (not just for one type of file), it's tested on three completely different kinds of data:

| Data Type | "Normal" Example | "Attack" Example |
|-----------|-------------------|-------------------|
| 📝 Text    | Ham (normal) SMS messages | Spam messages mixed in |
| 🖼️ Image   | Good carrot photos | Bad/rotten carrot photos mixed in |
| 🔊 Audio   | Dog barking sounds | Cat sounds mixed in |

Think of "ham," "good carrot," and "dog" as the stand-ins for *legitimate, expected data*, and "spam," "bad carrot," and "cat" as stand-ins for *attacks or intrusions* the system needs to catch.

---

## 5. The 6 Phases of the Project

The project was built one phase at a time, like building a house floor by floor. Each phase has its own Python file(s) and its own test suite to prove it works before moving to the next.

### Phase 0 — Preprocessing (`preprocessor.py`)
Takes the raw text/image/audio files and converts each one into a standard "package" of bytes, no matter what type it originally was:
```python
{ "filename": "dog_001.wav", "data": b"...", "type": "audio", "size": 132344 }
```
This makes every later step (encrypting, hashing, uploading) work the exact same way regardless of file type.

### Phase 1 — Encrypt → Fingerprint → Blockchain → Cloud (`encryption.py`, `blockchain.py`, `s3_handler.py`)
1. **Encrypt** the raw bytes using **AES-256**, a very strong, industry-standard encryption method. A random "IV" (a bit of randomness) is mixed in so that encrypting the same file twice never produces identical-looking scrambled data.
2. **Fingerprint** the *already-encrypted* bytes using **SHA-256** hashing — this fingerprint is called **Hash1**. (Important: the fingerprint is taken *after* encryption, never before — this matters for security reasons.)
3. **Write Hash1 into the blockchain** — a special local database (SQLite) that only ever allows *adding new entries*, never editing or deleting old ones. Each entry links to the previous one like a chain, so if anyone tampers with an old entry, the whole chain visibly breaks.
4. **Upload the encrypted file to AWS S3** (Amazon's cloud storage). This is deliberately the "risky" part of the system — S3 is assumed to be a place an attacker could potentially interfere with, which is exactly why the unbreakable fingerprint is kept safely elsewhere (in the blockchain), not in S3.

### Phase 2 — Buffalo Algorithm: Continuous Monitoring (`buffalo.py`)
After files are uploaded, the Buffalo algorithm continuously "patrols" the local dataset and the cloud storage:
- It builds a "normal profile" — an average fingerprint pattern — from known-good baseline files (ham messages, good carrots, dog sounds).
- It then compares every file's fingerprint pattern to that normal profile using a similarity score (0 to 1).
- Files that don't look similar enough get flagged, quarantined, or removed depending on how suspicious they are.

### Phase 3 — Cloud Auditing / File Access (`auditing.py`)
This is what happens every time someone actually wants to **open/download** a file:
1. Buffalo does a quick safety check on the request itself.
2. The encrypted file is downloaded fresh from S3.
3. A brand-new fingerprint (**Hash2**) is calculated from what was just downloaded.
4. The original fingerprint (**Hash1**) is pulled from the tamper-proof blockchain.
5. **Key Matching:** If Hash1 == Hash2, the file hasn't been touched since upload — it's safe to decrypt and hand back to the user. If they don't match, the system knows for certain the file was altered while sitting in the cloud, even if it looks completely normal on the outside.

### Phase 4 — Attack Simulation + Performance Testing (`dos_simulation.py`, `metrics.py`, `comparison.py`)
To prove the system actually works, this phase **deliberately attacks itself**:
- It corrupts files sitting in S3 on purpose (simulating a real hacker).
- It then re-runs Phase 3's checking process and confirms the system correctly detects "DATA INJECTED" every time.
- It also measures real-world performance (how fast encryption/decryption is, how much throughput the system can handle, memory/CPU usage, etc.) and compares these numbers against the original research paper's reported results.

### Phase 5 — Web Dashboard (Flask)
A simple website (built with Flask, a lightweight Python web framework) that lets you visually:
- Upload new files through a browser instead of the command line.
- Browse the blockchain like a ledger.
- See which cloud files are flagged as suspicious.
- View the performance comparison charts.

### Phase 6 — Final Integration & Submission
Bringing every phase together into one clean, end-to-end pipeline, cleaning up unused code, writing final documentation, and preparing academic submission materials (slides, reports).

---

## 6. Why Two Different Hashes? (Hash1 vs Hash2)

This trips a lot of people up at first, so here's the plain explanation:

- **Hash1** = the fingerprint taken **once**, right when the file is first uploaded. It's locked away forever in the blockchain and can never be changed.
- **Hash2** = a **brand-new fingerprint** taken **every single time** someone requests the file, based on whatever is *currently* sitting in cloud storage at that exact moment.

If nothing bad happened to the file in the meantime, Hash1 and Hash2 will always be identical — because hashing the same bytes always produces the same fingerprint. If they're different, something must have changed the file's bytes since upload — meaning tampering occurred.

---

## 7. Why Encrypt *Before* Hashing (not after)?

The fingerprint (Hash1) is deliberately calculated on the **encrypted (scrambled) version** of the file, not the original readable version. This has two benefits:
1. It protects the fingerprinting process itself from ever needing access to your real, private data.
2. It means the integrity check ("has this exact stored file been altered?") is checking the *actual bytes sitting in the cloud* — which is exactly what matters, since that's the part an attacker could get their hands on.

One side effect worth knowing: once a file is properly encrypted, its scrambled bytes look like pure random noise — there's no usable visual or textual pattern left for Buffalo to analyze for *content*. So for text and audio, Buffalo's cloud-monitoring step mainly checks *integrity* (has this file's byte-pattern shifted?) rather than *content* (is this a spam message vs. a ham message?) once the data is encrypted. Content-based detection (like spotting a "bad carrot" vs "good carrot") works best *before* encryption, on the raw file bytes — which is exactly when Phase 2's Buffalo scan happens for images.

---

## 8. Project Folder Structure

```
obhsb_project/
├── venv/                      ← Python virtual environment (isolated workspace)
├── .env                        ← Secret keys (AWS credentials, AES key) — never share this file
├── config.py                   ← Loads secrets from .env safely
├── requirements.txt             ← List of required Python packages
├── blockchain.db                ← The tamper-proof "notebook" (SQLite database)
│
├── modules/
│   ├── preprocessor.py          ← Phase 0: turns raw files into uniform byte packages
│   ├── encryption.py            ← Phase 1: AES encryption + hashing
│   ├── blockchain.py            ← Phase 1: the blockchain ledger
│   ├── s3_handler.py            ← Phase 1: talks to AWS S3 (upload/download)
│   ├── buffalo.py               ← Phase 2: the Buffalo monitoring algorithm
│   └── auditing.py              ← Phase 3: the file-access safety check
│
├── datasets/
│   ├── text/    (baseline = ham only, mixed = ham + spam)
│   ├── image/   (baseline = good carrots, mixed = good + bad carrots)
│   └── audio/   (baseline = dog sounds, mixed = dog + cat sounds)
│
├── profiles/                    ← Saved "what normal looks like" fingerprints per data type
│
├── pipeline_phase1.py            ← Runs Phase 1 end-to-end (small-scale demo)
├── upload_pipeline.py            ← Uploads the full dataset to S3 + blockchain (already used — S3 quota spent)
├── pipeline_phase2.py             ← Main pipeline entry point (Buffalo runs before upload, matching the paper)
├── run_phase4.py                  ← Runs the attack simulation + performance benchmarking
│
├── tests/                        ← Automated test files, one set per phase
│
└── outputs/                      ← Generated charts, comparison tables, and audit logs
```

---

## 9. Technology Used (and Why)

| Tool | What it's for | Why this one |
|------|----------------|----------------|
| **Python 3.14.3** | Main programming language | Simple, huge ecosystem for security/ML |
| **AWS S3** | Cloud file storage | Industry-standard, has a generous free tier |
| **SQLite** | The blockchain's underlying database | Lightweight, no server needed, perfect for simulating a blockchain locally |
| **pycryptodome** | AES-256 encryption | Reliable, well-tested cryptography library |
| **hashlib (built-in)** | SHA-256 fingerprinting | Standard, fast, cryptographically secure |
| **NumPy + scikit-learn** | Turning hashes into number vectors + comparing similarity | Needed for the Buffalo algorithm's math |
| **Flask** | The web dashboard | Lightweight Python web framework, easy to learn |
| **matplotlib** | Performance comparison charts | Standard Python plotting library |
| **librosa / soundfile** | Reading and processing audio files | Handles sample rates, trimming, format conversion |
| **Pillow (PIL)** | Reading and processing images | Standard image library in Python |
| **pandas** | Reading the text/CSV dataset | Standard tool for tabular data |

---

## 10. Environment Setup (Fedora 43 Linux)

### Step 1 — Install Python and system tools
```bash
sudo dnf install python3 python3-pip sqlitebrowser
```

### Step 2 — Create and activate a virtual environment
A virtual environment keeps this project's Python packages separate from the rest of your system.
```bash
python3 -m venv venv
source venv/bin/activate
```
(You'll need to run `source venv/bin/activate` every time you open a new terminal to work on this project.)

### Step 3 — Install required packages
```bash
pip install -r requirements.txt --break-system-packages
```
> On Fedora 43, `--break-system-packages` is often required because the system Python is protected from direct pip installs. This is safe here because we're working inside a virtual environment.

### Step 4 — Create your `.env` secrets file
Create a file named `.env` in the project's root folder:
```
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here
AWS_BUCKET_NAME=obhsb-project-anbu
AWS_REGION=ap-south-2
AES_SECRET_KEY=your_own_secret_string
```
**Never commit or share this file** — it contains your private AWS credentials.

### Step 5 — Set up your AWS S3 bucket (Free Tier)
1. Create a free AWS account if you don't already have one.
2. Create an S3 bucket (this project uses `obhsb-project-anbu` in the `ap-south-2` Hyderabad region).
3. Create an IAM user with S3 permissions (this project uses `obhsb-user`).
4. Copy the IAM user's access key and secret key into your `.env` file.

**⚠️ AWS S3 Free Tier limits to keep in mind:**
- **2,000 PUT/upload requests per month** — free
- **20,000 GET/download requests per month** — free
- **5 GB of storage** — free

This project's dataset (~1,895 files) uses almost the entire monthly upload quota, so:
- **Do not re-run the full upload pipeline** unless you're starting a new billing month.
- Downloads (GET requests) are cheap and safe to use freely for testing and demos.
- Always double check your AWS billing dashboard if you're unsure.

---

## 11. Running the Project

Run each phase from inside your project folder, with your virtual environment activated:

```bash
# Phase 1 demo (small-scale, safe to re-run — doesn't spend much S3 quota)
python pipeline_phase1.py

# Main pipeline (Buffalo scan → encrypt → blockchain → upload)
python pipeline_phase2.py

# Run the full test suite for a specific phase
python -m pytest tests/test_step1.py -v

# Run the DoS attack simulation + performance benchmark (Phase 4)
python run_phase4.py

# Launch the web dashboard (Phase 5)
python app.py
# then open http://127.0.0.1:5000 in your browser
```

---

## 12. The Ten Golden Rules (Never Break These)

These are the core design rules that keep the whole system consistent and secure:

1. Buffalo scans happen **after** files are uploaded to watch continuously (Phase 2), separate from the pre-upload content scan.
2. **Hash1 is always computed on the *encrypted* bytes**, never the original raw file.
3. Hash1 lives only in the **blockchain** (unchangeable) — never stored in S3.
4. S3 only ever stores **encrypted** files — this is treated as the "risky zone."
5. **Hash2** is always calculated freshly, at the exact moment someone requests a file.
6. Buffalo only ever works with **hashed/scrambled data** — it never sees anyone's private raw content.
7. The blockchain database only allows **adding new records** — updating or deleting old ones is never allowed.
8. "Malicious" test data = Spam text + Bad carrot images + Cat audio.
9. The AES encryption key is derived by hashing a secret passphrase with SHA-256 to get a proper 32-byte key.
10. Every encrypted file stores a random "IV" (initialization vector) glued to the front of it, so identical files never produce identical-looking encrypted output.

---

## 13. Reference — The Paper's Equations

| Equation | Formula | What it means in plain terms |
|----------|---------|-------------------------------|
| (1) | Dataset initialization | Organizing the raw dataset before processing |
| (2) | Buffalo attack detection (Pa*) | How similar a file's fingerprint is to "normal" |
| (3) | Buffalo attack neglection (Na*) | The gap between normal and attack similarity scores |
| (4) | Hash 1 calculation | The original fingerprint taken at upload time |
| (5) | AES encryption | Locking the file with a secret key |
| (6) | Hash 2 computation | The fresh fingerprint taken at access time |
| (7) | Key matching | Comparing Hash1 vs Hash2 to detect tampering |
| (8) | Resource usage measurement | Tracking CPU/memory cost of the system |

---

## 14. Results Summary

| Metric | Paper's Result | This Project's Result | Note |
|--------|------------------|--------------------------|------|
| Encryption time | ~3.5 ms | ~0.14 ms | Faster due to modern CPU hardware acceleration (AES-NI) |
| Decryption time | ~4.2 ms | ~0.13 ms | Same reason as above |
| Throughput | ~95 Mbps | ~3080 Mbps | Same reason as above |
| Confidential rate | 100% | 100% | Matches the paper exactly |
| Resource usage | ~7.5% | ~0.33% | Modern hardware is simply more efficient |
| Stability | ~99% | 100% | Measured on a stable local connection |
| Attack detection rate | — | 15/15 (100%) | Every simulated attack was caught |

All differences from the paper's numbers are presented honestly and explained by hardware improvements since 2024 — no numbers were adjusted to artificially match the original paper.

---

## 15. Frequently Asked Questions

**Q: Does Buffalo ever see my actual private files?**
No. Buffalo only ever works with SHA-256 hash fingerprints turned into number arrays — never the original readable content.

**Q: What happens if someone tampers with a file in S3?**
The next time anyone tries to access it, the freshly calculated Hash2 won't match the permanently stored Hash1, and the system will report "DATA INJECTED" instead of handing back the file.

**Q: What if someone tampers with the blockchain itself?**
Each entry in the blockchain is cryptographically linked to the one before it. Changing any single entry breaks that link, and a chain-verification check (`verify_chain()`) will immediately detect the break.

**Q: Why do encryption and decryption run so much faster than the numbers in the paper?**
Modern CPUs include built-in hardware acceleration for AES encryption (called AES-NI). The original 2024 paper likely ran on hardware without this acceleration, or used software-only encryption.

**Q: Can I re-upload the whole dataset again?**
Only if you're on a new AWS billing month — the free tier allows 2,000 uploads/month, and this dataset already uses nearly all of that quota.

---

## 16. Credits

- **Research paper:** Rajeev Kumar, M.P.S. Bhatia — *"An Intelligent Optimized Secure Blockchain Mechanism for Cloud Auditing,"* Expert Systems With Applications, Elsevier, 2024.
- **Implementation team:** Anbu Selvan M, Adithya B, Raghav S V
- **Project guide:** Raghav RS
- **Datasets used:** Kaggle — SMS Spam Dataset, Good/Bad Carrot Classification, Cats vs Dogs Audio Classification

---

*This README is meant to be understandable whether you're a fellow developer, an examiner, or a curious friend with no coding background. If anything is unclear, the phase-by-phase context cards in this project (`OBHSB_week1_complete.md` through `OBHSB_phase4_complete.md`) go into much deeper technical detail for each step.*
