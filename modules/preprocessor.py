import pandas as pd
import os

def preprocess_text(csv_path):
    results = []
    df = pd.read_csv(csv_path, encoding='latin-1')
    df.columns = [c.strip() for c in df.columns]

    # Auto detect message column
    msg_col = None
    for col in ['message', 'text', 'sms', 'v2']:
        if col in df.columns:
            msg_col = col
            break

    df = df.dropna(subset=[msg_col])

    for _, row in df.iterrows():
        text = str(row[msg_col]).strip()
        data_bytes = text.encode('utf-8')
        if len(data_bytes) == 0:
            continue
        results.append({
            'filename': f"text_{len(results):04d}.txt",
            'data': data_bytes,
            'type': 'text',
            'size': len(data_bytes)
        })
    return results

from PIL import Image
import io

def preprocess_image(folder_path):
    results = []
    valid_ext = ('.jpg', '.jpeg', '.png', '.bmp')

    for filename in os.listdir(folder_path):
        if not filename.lower().endswith(valid_ext):
            continue
        img_path = os.path.join(folder_path, filename)
        try:
            img = Image.open(img_path).convert('RGB')
            img = img.resize((224, 224))
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=85)
            data_bytes = buffer.getvalue()
            results.append({
                'filename': filename,
                'data': data_bytes,
                'type': 'image',
                'size': len(data_bytes)
            })
        except Exception as e:
            print(f"Skipping {filename}: {e}")
    return results
    
import librosa
import soundfile as sf
import numpy as np

def preprocess_audio(folder_path):
    results = []
    TARGET_SR = 22050
    TARGET_SAMPLES = TARGET_SR * 3  # 3 seconds = 66150 samples

    for filename in os.listdir(folder_path):
        if not filename.lower().endswith('.wav'):
            continue
        audio_path = os.path.join(folder_path, filename)
        try:
            audio, sr = librosa.load(audio_path, sr=TARGET_SR, mono=True)

            # Trim or pad to exactly 3 seconds
            if len(audio) > TARGET_SAMPLES:
                audio = audio[:TARGET_SAMPLES]
            else:
                audio = np.pad(audio, (0, TARGET_SAMPLES - len(audio)))

            # Normalize
            if np.max(np.abs(audio)) > 0:
                audio = audio / np.max(np.abs(audio))

            # Write to bytes
            buffer = io.BytesIO()
            sf.write(buffer, audio, TARGET_SR, format='WAV')
            data_bytes = buffer.getvalue()

            results.append({
                'filename': filename,
                'data': data_bytes,
                'type': 'audio',
                'size': len(data_bytes)
            })
        except Exception as e:
            print(f"Skipping {filename}: {e}")
    return results

