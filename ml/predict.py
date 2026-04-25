import json
import joblib
import pandas as pd
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

PORT = 5002

# Load model and scaler
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')

print("Loading ML models for Prediction Server...")
if not os.path.exists(model_path) or not os.path.exists(scaler_path):
    print("❌ Error: model.pkl or scaler.pkl missing. Run train.py first.")
    exit(1)

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)
print("✅ Models loaded successfully.")

# Feature names in the exact order trained
FEATURE_COLS = [
    'req_count_1m', 'req_count_5m', 'avg_req_interval', 'std_req_interval',
    'burst_max_5s', 'unique_endpoints', 'unique_methods', 'get_ratio',
    'post_ratio', '4xx_count', '5xx_count', '401_count', '403_count',
    '404_count', 'avg_latency', 'max_latency', 'bytes_sent', 'avg_payload_size',
    'failed_auth_count', 'token_changes', 'distinct_user_agents',
    'admin_route_hits', 'sensitive_route_hits'
]

class MLPredictHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/predict':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                
                # Extract features from request
                features = []
                for col in FEATURE_COLS:
                    features.append(float(data.get(col, 0.0)))
                
                # Reshape to 2D array for sklearn
                df_predict = pd.DataFrame([features], columns=FEATURE_COLS)
                
                # Scale
                X_scaled = scaler.transform(df_predict)
                
                # Isolation Forest decision_function returns anomaly score
                # Less than 0 is anomaly, greater than 0 is normal.
                # Lower scores -> higher anomaly.
                decision_score = model.decision_function(X_scaled)[0]
                
                # Normalize to 0-100 (where 100 = max anomaly)
                # Max normal score usually ~ 0.15, min extreme anomaly ~ -0.4
                # We normalize it so decision_score = 0 becomes score 50 (borderline)
                ml_score = 0
                if decision_score < 0:
                    # Invert and scale so -0.4 becomes ~ 100
                    ml_score = min(100, 50 + abs(decision_score) * 125)
                else:
                    # Positive values scale from 0 to 49
                    ml_score = max(0, 50 - decision_score * 200)

                response = {
                    "mlScore": max(0, min(100, ml_score)), # clip between 0-100
                    "decisionScore": decision_score
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=MLPredictHandler, port=PORT):
    server_address = ('127.0.0.1', port)
    httpd = server_class(server_address, handler_class)
    print(f"🌲 Isolation Forest ML Server running on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
