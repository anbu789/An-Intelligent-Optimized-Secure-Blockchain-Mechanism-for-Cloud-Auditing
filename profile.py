python -c "
import numpy as np
from pathlib import Path
from modules.buffalo import sha256_bytes, hash_to_vector

# Get only ham txt files
txt_folder = Path('datasets/text/mixed/txt_files')
ham_files = sorted([f for f in txt_folder.iterdir() if f.name.startswith('ham_')])
print(f'Found {len(ham_files)} ham files')

# Build profile — SHA-256 each file → vector → mean
vectors = []
for f in ham_files:
    raw = f.read_bytes()
    hex_hash = sha256_bytes(raw)
    vec = hash_to_vector(hex_hash)
    vectors.append(vec)

profile = np.mean(vectors, axis=0)
print(f'Text profile shape: {profile.shape}, mean: {profile.mean():.4f}')

# Save
import os
os.makedirs('profiles', exist_ok=True)
np.save('profiles/text_normal_profile.npy', profile)
print('Saved → profiles/text_normal_profile.npy')
"

python -c "
import numpy as np
import os
from pathlib import Path
from modules.buffalo import load_or_build_profile

# Image profile — from baseline folder (good carrots only)
print('Building image profile...')
image_profile = load_or_build_profile(
    data_type   = 'image',
    source      = 'datasets/image/baseline',
    profile_dir = 'profiles'
)
print(f'Image profile shape: {image_profile.shape}, mean: {image_profile.mean():.4f}')

# Audio profile — from baseline folder (dog only)
print('Building audio profile...')
audio_profile = load_or_build_profile(
    data_type   = 'audio',
    source      = 'datasets/audio/baseline',
    profile_dir = 'profiles'
)
print(f'Audio profile shape: {audio_profile.shape}, mean: {audio_profile.mean():.4f}')

print('Done!')
"

python -c "
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(levelname)-8s  %(message)s')
from modules.auditing import audit_file
result = audit_file('ham_0001.txt', 'text')
print(f'Verdict : {result[\"verdict\"]}')
print(f'Content : {result.get(\"plaintext\", \"N/A\")}')
"

python -c "
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(levelname)-8s  %(message)s')

# Temporarily patch download_bytes to return garbage
import modules.auditing as aud
original_download = aud.download_bytes

def fake_download(s3_key):
    return b'ATTACKER_INJECTED_GARBAGE_BYTES_12345'

aud.download_bytes = fake_download

from modules.auditing import audit_file
result = audit_file('ham_0001.txt', 'text')
print(f'Verdict : {result[\"verdict\"]}')
print(f'Action  : {result[\"action_taken\"]}')
"
