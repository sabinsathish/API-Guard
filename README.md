# API-Guard: Hybrid Multi-Source Secure API Gateway

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-success.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![MongoDB](https://img.shields.io/badge/database-MongoDB-green.svg)

API-Guard is a high-performance, intelligent API Gateway that protects your internal and external services using a Hybrid Threat Detection Engine. It combines traditional Deterministic Rule-Based Detection (Rate Limiting, IP Blacklisting) with Unsupervised Machine Learning (Isolation Forest) to catch stealthy, behavioral anomalies that standard firewalls miss.

---

## Theme 1: Cybersecurity & Digital Trust

### Problem Statement

Modern applications rely heavily on APIs, which act as the backbone for communication between services, clients, and external platforms. However, APIs are highly vulnerable to various security threats such as unauthorized access, abuse, data breaches, and denial-of-service (DoS) attacks. Traditional security mechanisms often fail to detect sophisticated or slow-moving attacks that mimic normal user behavior.

**Problem**  
Modern applications rely heavily on APIs, which are vulnerable to attacks such as unauthorized access, abuse, and denial-of-service.

**Challenge**  
Develop a secure API gateway that includes:  
• Authentication (e.g., JWT-based access control)  
• Rate limiting to prevent abuse  
• Logging and monitoring of suspicious activities  

**Goal**  
Enhance backend security by protecting APIs and providing visibility into potential threats.

### Explanation

In real-world systems, APIs are constantly exposed to the internet, making them prime targets for attackers. While basic protections like authentication and rate limiting help, they are often insufficient against advanced threats such as behavioral anomalies, token misuse, or coordinated attack patterns.

This project addresses the gap by introducing a hybrid approach:
- Rule-based systems handle known attack patterns instantly.
- Machine learning detects unknown or evolving threats by analyzing behavior.

The goal is not just to block attacks, but to provide real-time visibility, intelligent detection, and adaptive security for modern API-driven architectures.

---

## Key Features

* Hybrid Threat Engine: Calculates a combined "Risk Score" based on hard rules (65% weight) and ML anomaly detection (35% weight).
* ML Behavioral Profiling: Uses an Isolation Forest algorithm evaluating 23 distinct behavioral features per IP (request intervals, error rates, token swaps, endpoint hunting).
* Real-Time Security Dashboard: A live-updating UI built with Chart.js and Socket.io to monitor traffic and track attackers in real-time.
* Integrated Attack Simulator: A built-in testing suite to safely launch DoS, Brute Force, and Route Scanning attacks against your own gateway to visualize the defenses.
* Online ML Retraining: Extract live traffic logs from your MongoDB database to retrain and specialize the ML model for your specific API's baseline traffic.
* Dynamic API Proxying: Easily register and route traffic to external APIs (like OpenAI, Stripe) or internal microservices securely.

---

## Architecture

1. Gateway Server (`server.js`): The main Node.js/Express entry point that intercepts all traffic.
2. Threat Engine (`threatEngine.js`): Tracks request histories in memory, calculates rule penalties, and fetches ML scores.
3. ML Microservice (`ml/predict.py`): A Python-based prediction server running on port 5002 that scores behavioral vectors.
4. MongoDB Data Layer (`models/Log.js`): Persistent storage of every request for auditing and ML retraining.

---

## Getting Started

### 1. Prerequisites
Ensure you have the following installed on your system:
*   [Node.js](https://nodejs.org/) (v18 or higher)
*   [Python](https://www.python.org/downloads/) (v3.10 or higher)
*   *Optional but recommended:* [MongoDB Compass](https://www.mongodb.com/try/download/compass) for viewing your persistent data.

### 2. Installation
Clone the repository and install the dependencies for both Node.js and Python.

```bash
# Install Node.js dependencies
npm install

# Install Python ML dependencies
pip install -r requirements.txt
```

*(Note: The project uses an automatic fallback `MongoMemoryServer`, so installing a full MongoDB instance is not strictly required to run the demo).*

### 3. Start the System
To start the Gateway, the real-time Dashboard, and the Machine Learning microservice simultaneously, run:

```bash
cd gateway
node server.js
```

You will see output indicating that both the Gateway (Port 3000) and the ML Server (Port 5002) have started successfully.

---

## How to Use the Suite

Once the server is running, you can access the following web interfaces:

### 1. The Security Dashboard
**URL:** [http://localhost:3000/dashboard](http://localhost:3000/dashboard)
*   Monitor Live Traffic (RPS), Success Rates, and Status Breakdowns.
*   Watch the **Live Threat Feed** update in real-time as attackers hit the system.

### 2. The Attack Simulator
**URL:** [http://localhost:3000/attack](http://localhost:3000/attack)
*   Use this UI to simulate malicious behavior.
*   Try the **"Full Attack Demo"** to run through Normal Traffic, Rate Abuse, Route Scanning, Brute Force, and DoS Floods.
*   Watch how the gateway reacts and eventually blocks the attacking IPs (returning `403 Forbidden`).

### 3. The API Tester
**URL:** [http://localhost:3000/api-tester](http://localhost:3000/api-tester)
*   A built-in Postman-like tool to manually test your protected endpoints.
*   Try testing valid and invalid JWT tokens to trigger the `BROKEN_AUTH` threat rules.

---

## Machine Learning: Training & Fine-Tuning

API-Guard comes with a pre-trained model (`model.pkl`), but you should train it on your own traffic data for the best results.

### Method 1: Train on Live Database Traffic (Recommended)
After you have run some traffic (or used the Attack Simulator) to populate your database with logs:
```bash
cd ml
python train_from_mongo.py
```
This script connects to your MongoDB, extracts the 23 behavioral features for every IP, and retrains the Isolation Forest model specifically on your real-world traffic.

### Method 2: Train on Synthetic Data
If you want to generate a massive synthetic dataset to stress-test the model:
```bash
cd ml
python generate_dataset.py
python train.py
python evaluate.py
```

---

## Viewing Your Database
By default, the system runs a persistent database on port `27018` to ensure your ML training data isn't lost.
1. Open **MongoDB Compass**.
2. Connect to: `mongodb://127.0.0.1:27018/`
3. Browse the `secureGateway` database and the `logs` collection.

*(To manually wipe the database, run `node clearLogs.js` from the gateway folder).*

---

## Security Disclaimer
This software is intended for educational purposes, internal network protection, and security research. Do not use the Attack Simulator against external targets you do not have explicit permission to test.
