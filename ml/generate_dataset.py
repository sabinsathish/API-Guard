import pandas as pd
import numpy as np

# Total samples
N_NORMAL = 8000
N_ATTACK = 2000

print(f"Generating Synthetic Behavior Window Dataset...")
print(f"Normal samples: {N_NORMAL}")
print(f"Attack samples: {N_ATTACK}")

# ──────────────────────────────────────────────────────────────────────────────
# Normal Traffic Distribution
# ──────────────────────────────────────────────────────────────────────────────
df_normal = pd.DataFrame({
    'req_count_1m': np.random.randint(1, 40, N_NORMAL),
    'req_count_5m': np.random.randint(5, 120, N_NORMAL),
    'avg_req_interval': np.random.uniform(500, 5000, N_NORMAL),
    'std_req_interval': np.random.uniform(10, 1000, N_NORMAL),
    'burst_max_5s': np.random.randint(1, 8, N_NORMAL),
    'unique_endpoints': np.random.randint(1, 15, N_NORMAL),
    'unique_methods': np.random.randint(1, 3, N_NORMAL),
    'get_ratio': np.random.uniform(0.7, 1.0, N_NORMAL),
    'post_ratio': np.random.uniform(0.0, 0.3, N_NORMAL),
    '4xx_count': np.random.choice([0, 1, 2], N_NORMAL, p=[0.9, 0.08, 0.02]),
    '5xx_count': np.random.choice([0, 1], N_NORMAL, p=[0.99, 0.01]),
    '401_count': np.random.choice([0, 1], N_NORMAL, p=[0.98, 0.02]),
    '403_count': np.random.choice([0, 1], N_NORMAL, p=[0.99, 0.01]),
    '404_count': np.random.choice([0, 1, 2], N_NORMAL, p=[0.95, 0.04, 0.01]),
    'avg_latency': np.random.uniform(10, 120, N_NORMAL),
    'max_latency': np.random.uniform(20, 300, N_NORMAL),
    'bytes_sent': np.random.uniform(100, 5000, N_NORMAL),
    'avg_payload_size': np.random.uniform(0, 500, N_NORMAL),
    'failed_auth_count': np.random.choice([0, 1], N_NORMAL, p=[0.98, 0.02]),
    'token_changes': np.random.choice([0, 1], N_NORMAL, p=[0.95, 0.05]),
    'distinct_user_agents': np.random.choice([1, 2], N_NORMAL, p=[0.98, 0.02]),
    'admin_route_hits': np.random.choice([0, 1, 2], N_NORMAL, p=[0.95, 0.04, 0.01]), # Admins exist
    'sensitive_route_hits': np.random.randint(0, 3, N_NORMAL),
})


# ──────────────────────────────────────────────────────────────────────────────
# Attack Traffic Distributions Mix (Brute Force, DoS, Scanning, Abuse)
# ──────────────────────────────────────────────────────────────────────────────
# We build an array of varied anomalies
def generate_attack(n):
    return pd.DataFrame({
        'req_count_1m': np.random.randint(60, 400, n),          # High frequency 
        'req_count_5m': np.random.randint(150, 1500, n),
        'avg_req_interval': np.random.uniform(5, 100, n),       # Very fast
        'std_req_interval': np.random.uniform(0, 5, n),         # Bot-like constant pace
        'burst_max_5s': np.random.randint(20, 100, n),          # Huge bursts
        'unique_endpoints': np.random.randint(10, 80, n),       # Scanning lots of endpoints
        'unique_methods': np.random.randint(2, 5, n),
        'get_ratio': np.random.uniform(0.1, 0.9, n),            
        'post_ratio': np.random.uniform(0.1, 0.9, n),
        '4xx_count': np.random.randint(10, 300, n),             # Mass errors
        '5xx_count': np.random.randint(0, 50, n),
        '401_count': np.random.randint(5, 100, n),              # Brute forcing auth
        '403_count': np.random.randint(5, 50, n),               # Access denied abuse
        '404_count': np.random.randint(20, 150, n),             # Scanning missing files
        'avg_latency': np.random.uniform(80, 800, n),           # Straining server
        'max_latency': np.random.uniform(400, 3000, n),
        'bytes_sent': np.random.uniform(2000, 50000, n),        # Large payloads
        'avg_payload_size': np.random.uniform(500, 8000, n), 
        'failed_auth_count': np.random.randint(10, 100, n),     # Brute force login
        'token_changes': np.random.randint(2, 15, n),           # Stolen token testing
        'distinct_user_agents': np.random.randint(2, 10, n),    # Spoofing agents
        'admin_route_hits': np.random.randint(5, 40, n),        # Aggressive admin hunting
        'sensitive_route_hits': np.random.randint(10, 50, n),
    })

df_attack = generate_attack(N_ATTACK)

df_all = pd.concat([df_normal, df_attack], ignore_index=True)
df_all = df_all.sample(frac=1, random_state=42).reset_index(drop=True)

df_all.to_csv('dataset.csv', index=False)
print("dataset.csv successfully created with 23 features.")
