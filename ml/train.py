import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

print("🚀 Starting Hybrid Threat Detection ML Training...")

# 1. Load Data
dataset_path = 'dataset.csv'
if not os.path.exists(dataset_path):
    print(f"❌ Error: {dataset_path} not found. Run generate_dataset.py first.")
    exit(1)

df = pd.read_csv(dataset_path)

# 2. Scaling
# StandardScaler standardizes features by removing the mean and scaling to unit variance
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)

# 3. Train Isolation Forest
print("🌲 Training Isolation Forest (n_estimators=200, contamination=0.02)...")
model = IsolationForest(
    n_estimators=200,
    contamination=0.02,
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

# 4. Save Artifacts
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(model, 'model.pkl')

print("✅ Training complete. Saved 'scaler.pkl' and 'model.pkl'.")
