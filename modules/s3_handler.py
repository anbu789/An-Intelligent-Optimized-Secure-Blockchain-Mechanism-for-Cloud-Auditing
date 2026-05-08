import boto3
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_BUCKET_NAME, AWS_REGION

# ─────────────────────────────────────────────
# EXISTING FUNCTIONS FROM WEEK 1 (unchanged)
# ─────────────────────────────────────────────

def get_s3_client():
    return boto3.client(
        's3',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )

def upload_bytes(data_bytes, s3_key):
    """Upload raw bytes to S3 at the given key path."""
    client = get_s3_client()
    client.put_object(Bucket=AWS_BUCKET_NAME, Key=s3_key, Body=data_bytes)
    print(f"  [s3] Uploaded: {s3_key} ({len(data_bytes)} bytes)")

def download_bytes(s3_key):
    """Download bytes from S3 at the given key path."""
    client = get_s3_client()
    response = client.get_object(Bucket=AWS_BUCKET_NAME, Key=s3_key)
    return response['Body'].read()

def delete_file(s3_key):
    """Delete a file from S3."""
    client = get_s3_client()
    client.delete_object(Bucket=AWS_BUCKET_NAME, Key=s3_key)
    print(f"  [s3] Deleted: {s3_key}")

def list_files(prefix=''):
    """List all files in S3 under the given prefix (folder path)."""
    client = get_s3_client()
    response = client.list_objects_v2(Bucket=AWS_BUCKET_NAME, Prefix=prefix)
    return [obj['Key'] for obj in response.get('Contents', [])]


# ─────────────────────────────────────────────
# NEW — Phase 1 Helper
# upload_encrypted_file()
#
# Combines two jobs in one clean call:
#   1. Build the correct s3_key from data_type + filename
#   2. Upload the encrypted bytes to S3
#
# Convention:
#   data_type="text",  filename="text_0001.txt" → "encrypted/text/text_0001.txt"
#   data_type="image", filename="carrot_01.jpg" → "encrypted/image/carrot_01.jpg"
#   data_type="audio", filename="dog_001.wav"   → "encrypted/audio/dog_001.wav"
#
# Input : encrypted_bytes = IV(16) + ciphertext  ← from encrypt_bytes()
#         filename        = original filename from preprocessor
#         data_type       = "text" / "image" / "audio"
#
# Output: s3_key (string) — the full path where file was stored in S3
#
# IMPORTANT:
#   ✅ Only encrypted bytes ever go to S3
#   ❌ Raw bytes never uploaded
#   ❌ Hash1 never uploaded (stays in blockchain only)
# ─────────────────────────────────────────────
def upload_encrypted_file(encrypted_bytes: bytes, filename: str, data_type: str) -> str:

    # Step 1 — Build S3 key
    # "encrypted/" + "text" + "/" + "text_0001.txt"
    # → "encrypted/text/text_0001.txt"
    s3_key = f"encrypted/{data_type}/{filename}"

    # Step 2 — Upload to S3
    upload_bytes(encrypted_bytes, s3_key)

    # Step 3 — Return s3_key so pipeline knows where file lives
    return s3_key


# ─────────────────────────────────────────────
# NEW — Phase 1 Helper
# download_encrypted_file()
#
# Reverse of upload_encrypted_file()
# Used in Phase 3 (cloud auditing) to download file for Hash2 computation
#
# Input : filename  = original filename
#         data_type = "text" / "image" / "audio"
# Output: encrypted_bytes (IV + ciphertext) — exactly what was uploaded
# ─────────────────────────────────────────────
def download_encrypted_file(filename: str, data_type: str) -> bytes:

    # Rebuild the same s3_key using same convention
    s3_key = f"encrypted/{data_type}/{filename}"

    encrypted_bytes = download_bytes(s3_key)
    print(f"  [s3] Downloaded: {s3_key} ({len(encrypted_bytes)} bytes)")

    return encrypted_bytes
