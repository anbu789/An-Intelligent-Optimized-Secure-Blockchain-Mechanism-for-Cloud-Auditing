import pandas as pd

df = pd.read_csv('datasets/text/mixed/spam.csv', encoding='latin-1', usecols=['v1', 'v2'])
df.columns = ['label', 'message']
df = df.dropna()

print(f"Total rows: {len(df)}")
print(f"Ham rows:  {len(df[df['label'] == 'ham'])}")
print(f"Spam rows: {len(df[df['label'] == 'spam'])}")

# Baseline — ham only (normal)
baseline = df[df['label'] == 'ham'][['message']]
baseline.to_csv('datasets/text/baseline/ham_only.csv', index=False)
print("Baseline saved → datasets/text/baseline/ham_only.csv")

# Mixed — ham + spam (normal + attack)
df[['label', 'message']].to_csv('datasets/text/mixed/spam_ham_mixed.csv', index=False)
print("Mixed saved → datasets/text/mixed/spam_ham_mixed.csv")
