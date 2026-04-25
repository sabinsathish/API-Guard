import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import confusion_matrix, classification_report
import os

def evaluate():
    print("Generating Confusion Matrix for the Isolation Forest Model...")
    
    # 1. Load data and models
    try:
        model = joblib.load('model.pkl')
        scaler = joblib.load('scaler.pkl')
        df = pd.read_csv('dataset.csv')
    except Exception as e:
        print(f"Error: {e}")
        return

    # 2. Reconstruct true labels (based on how generate_dataset.py works)
    # generate_dataset.py creates 8000 normal then 2000 attack
    # Normal = 1, Anomaly = -1
    n_total = len(df)
    n_attack = 2000 # This matches generate_dataset.py N_ATTACK
    n_normal = n_total - n_attack
    
    y_true = np.array([1]*n_normal + [-1]*n_attack)
    
    # 3. Predict
    X_scaled = scaler.transform(df)
    y_pred = model.predict(X_scaled)
    
    # 4. Generate Matrix
    cm = confusion_matrix(y_true, y_pred)
    
    print("\n" + "="*45)
    print("         ML MODEL PERFORMANCE MATRIX")
    print("="*45)
    print(f"{'Metric':<25} {'Value':<15}")
    print("-" * 45)
    
    total = len(y_true)
    correct = np.sum(y_true == y_pred)
    accuracy = (correct / total) * 100
    
    print(f"{'Overall Accuracy':<25} {accuracy:.2f}%")
    print(f"{'True Anomalies Caught':<25} {cm[0][0]}")
    print(f"{'Missed Anomalies':<25} {cm[0][1]}")
    print(f"{'False Alarms':<25} {cm[1][0]}")
    print(f"{'Correct Normals':<25} {cm[1][1]}")
    print("-" * 45)
    
    print("\nDetailed Classification Report:")
    print(classification_report(y_true, y_pred, target_names=['Anomaly', 'Normal']))
    
    print("="*45)

if __name__ == "__main__":
    evaluate()
