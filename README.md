# 🛡️ Hybrid Multi-Source Secure API Gateway

A production-ready API Gateway that routes, authenticates, rate-limits, and threat-monitors both Internal APIs (port 5000) and External public APIs (JSONPlaceholder, DummyJSON) through a single secure entry point.

---

## 🚀 Quick Start

Open **two terminal windows**:

**Terminal 1 — Start the Internal Backend (port 5000):**
```cmd
cd secure-api-gateway\backend
node server.js
```

**Terminal 2 — Start the Gateway (port 3000):**
```cmd
cd secure-api-gateway\gateway
node server.js
```

Then open: **http://localhost:3000**

---

## 📁 Project Structure

```
secure-api-gateway/
├── gateway/                  ← Main gateway (port 3000)
│   ├── middleware/
│   │   ├── auth.js           ← JWT validation + role extraction
│   │   ├── roleCheck.js      ← RBAC factory middleware
│   │   ├── rateLimiter.js    ← Per-route rate limits
│   │   ├── threatIdentifier.js ← SQL/XSS/scan detection
│   │   ├── ipBlocker.js      ← IP block enforcement
│   │   └── logger.js         ← Request logging to MongoDB
│   ├── routes/
│   │   ├── authRoutes.js     ← POST /auth/login, /auth/register
│   │   ├── internalRoutes.js ← Proxy → localhost:5000
│   │   ├── externalRoutes.js ← Proxy → JSONPlaceholder / DummyJSON 
│   │   └── attackRoutes.js   ← Demo attack simulation
│   ├── services/
│   │   ├── threatEngine.js   ← Dual-axis risk scoring engine
│   │   ├── metricsService.js ← Live metrics counters
│   │   ├── logService.js     ← MongoDB log writer
│   │   └── socketService.js  ← Socket.io events
│   ├── models/
│   │   ├── User.js           ← User model (PBKDF2 passwords)
│   │   └── Log.js            ← Request log model
│   ├── .env                  ← Environment variables
│   └── server.js             ← Main entry point
│
├── backend/                  ← Internal backend (port 5000)
│   └── server.js
│
├── dashboard/                ← Admin dashboard UI
├── login/                    ← Login page
├── api-tester/               ← API testing UI
├── attack-ui/                ← Attack simulator
└── attacker-ui/              ← Python attacker terminal
```

---

## 🌐 API Routes

### Internal APIs (proxied to port 5000)

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/api/internal/products` | None | Product catalog |
| GET | `/api/internal/users/public` | None | Public user list |
| GET | `/api/internal/profile` | JWT | Authenticated user profile |
| POST | `/api/internal/orders` | JWT | Place an order |
| GET | `/api/internal/admin/dashboard` | Admin JWT | Admin stats |
| DELETE | `/api/internal/admin/user/:id` | Admin JWT | Delete user |

### External APIs (proxied to public APIs)

| Route | Upstream |
|-------|----------|
| `/api/external/posts` | JSONPlaceholder |
| `/api/external/users` | JSONPlaceholder |
| `/api/external/comments` | JSONPlaceholder |
| `/api/external/store/products` | DummyJSON |

---

## 🔐 Authentication

**Login to get a JWT:**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"Admin@123\"}"
```

**Use the token:**
```bash
curl http://localhost:3000/api/internal/profile \
  -H "Authorization: Bearer <token>"
```

**Default credentials:**
- `admin` / `Admin@123` (admin role)

---

## 🔒 Rate Limits

| Route | Limit |
|-------|-------|
| Global | 80 req/min (soft), 120 req/min (hard) |
| `POST /auth/login` | 4/min soft, 6/min hard |
| `POST /api/internal/orders` | 8/min soft, 12/min hard |
| `/api/external/*` | 40/min soft, 60/min hard |

---

## 🎯 Threat Detection

**4-Level Classification:**

| Score | Level | Response |
|-------|-------|----------|
| 0–20 | LOW | Log only |
| 20–40 | MEDIUM | Throttle |
| 40–70 | HIGH | 5-min block + alert |
| 70–100 | CRITICAL | Immediate block + alert |

**Detected Attacks:**
- Brute Force Login
- Broken Auth (expired/forged/weak tokens)
- DoS Flood (velocity-based)
- SQL Injection (regex pattern scanning)
- XSS Payloads (reflected + DOM)
- Route Scanning (phpmyadmin, .env, .git)
- Admin Access Probing
- External API Scraping

---

## 🖥️ UI Pages

| URL | Page |
|-----|------|
| `http://localhost:3000` | → Redirects to Login |
| `http://localhost:3000/login` | Login / Register |
| `http://localhost:3000/dashboard` | Admin Dashboard |
| `http://localhost:3000/api-tester` | API Tester |
| `http://localhost:3000/attack` | Attack Simulator |
| `http://localhost:3000/attacker` | Python Attacker Terminal |

---

## 🔬 Demo Scenarios

```bash
# 1. Legit user gets products
curl http://localhost:3000/api/internal/products

# 2. Admin dashboard (need admin token)
TOKEN=$(curl -s -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"Admin@123\"}" | node -e "process.stdin.resume();process.stdin.pipe(require('stream').Transform.call(Object.create(require('stream').Transform.prototype), {transform(c,e,cb){cb(null,JSON.parse(c).token)}}));")
curl http://localhost:3000/api/internal/admin/dashboard -H "Authorization: Bearer $TOKEN"

# 3. External API (no auth needed)
curl http://localhost:3000/api/external/posts/1

# 4. External DummyJSON store
curl http://localhost:3000/api/external/store/products

# 5. Trigger brute force (from Attack Simulator or):
for i in {1..10}; do curl -s -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"wrong"}'; done
```

---

## 🌍 Environment Variables (`gateway/.env`)

```
PORT=3000
BACKEND_URL=http://localhost:5000
JWT_SECRET=super-secure-secret-change-in-prod
MONGO_URI=mongodb://127.0.0.1:27017/secureGateway
```
