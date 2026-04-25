import pandas as pd
import numpy as np
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime, timedelta

# Configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://127.0.0.1:27018/secureGateway')
COLLECTION = 'logs'

def extract_features_from_db():
    print(f"Connecting to MongoDB: {MONGO_URI}")
    client = MongoClient(MONGO_URI)
    db = client.get_database()
    logs_col = db[COLLECTION]

    # Fetch last 1 hour of logs (or all available)
    logs = list(logs_col.find())
    if not logs:
        print("Error: No logs found in database. Run some traffic first!")
        return None

    print(f"Found {len(logs)} real traffic logs. Processing features...")
    
    # Convert to DataFrame for processing
    df_logs = pd.DataFrame(logs)
    df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
    
    # Group by IP to create behavioral windows
    ips = df_logs['ip'].unique()
    features_list = []

    for ip in ips:
        ip_logs = df_logs[df_logs['ip'] == ip].sort_values('timestamp')
        if len(ip_logs) < 2: continue # Skip single requests
        
        # Calculate features similar to gateway logic
        now = datetime.now()
        intervals = ip_logs['timestamp'].diff().dt.total_seconds().dropna() * 1000
        
        f = {
            'req_count_1m': len(ip_logs[ip_logs['timestamp'] > (now - timedelta(minutes=1))]),
            'req_count_5m': len(ip_logs),
            'avg_req_interval': intervals.mean() if not intervals.empty else 0,
            'std_req_interval': intervals.std() if len(intervals) > 1 else 0,
            'burst_max_5s': 0, # Approximation
            'unique_endpoints': ip_logs['endpoint'].nunique(),
            'unique_methods': ip_logs['method'].nunique(),
            'get_ratio': len(ip_logs[ip_logs['method'] == 'GET']) / len(ip_logs),
            'post_ratio': len(ip_logs[ip_logs['method'] == 'POST']) / len(ip_logs),
            '4xx_count': len(ip_logs[(ip_logs['status'] >= 400) & (ip_logs['status'] < 500)]),
            '5xx_count': len(ip_logs[ip_logs['status'] >= 500]),
            '401_count': len(ip_logs[ip_logs['status'] == 401]),
            '403_count': len(ip_logs[ip_logs['status'] == 403]),
            '404_count': len(ip_logs[ip_logs['status'] == 404]),
            'avg_latency': ip_logs['responseMs'].mean(),
            'max_latency': ip_logs['responseMs'].max(),
            'bytes_sent': len(ip_logs) * 500, # Approximation
            'avg_payload_size': 250, # Approximation
            'failed_auth_count': len(ip_logs[ip_logs['status'] == 401]),
            'token_changes': 0,
            'distinct_user_agents': ip_logs['userAgent'].nunique(),
            'admin_route_hits': len(ip_logs[ip_logs['endpoint'].str.contains('admin', case=False)]),
            'sensitive_route_hits': len(ip_logs[ip_logs['endpoint'].str.contains('config|env|php|wp', case=False)])
        }
        features_list.append(f)

    return pd.DataFrame(features_list)

def train_on_real_data():
    df_features = extract_features_from_db()
    if df_features is None or df_features.empty: return

    print(f"Extracted features for {len(df_features)} unique entities.")
    
    # Scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_features)

    # Train (Contamination 0.05 - assume 5% of real traffic is suspicious)
    print("Training Isolation Forest on LIVE data...")
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X_scaled)

    # Save
    joblib.dump(scaler, 'scaler.pkl')
    joblib.dump(model, 'model.pkl')
    print("✅ Model updated with LIVE traffic data!")

if __name__ == "__main__":
    train_on_real_data()
