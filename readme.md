# Aapki Nazar: Web Application SOC & Autonomous OWASP WAF Defense Platform

[![Node.js](https://img.shields.io/badge/Node.js-18.x+-green.svg)](https://nodejs.org/)
[![OWASP CRS](https://img.shields.io/badge/Sensor-OWASP%20CRS%20v3.3%2Fv4.0-blue.svg)](https://coreruleset.org/)
[![Gateway Defense](https://img.shields.io/badge/Defense-Active%20403%20Firewall-crimson.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

**Aapki Nazar** ("Your Watch" / "Your Vision") is an **Autonomous Web Application Security Operations Center (SOC)** and active API gateway defense platform. 

Sitting directly in the inbound traffic path, it inspects live HTTP traffic using an **OWASP Core Rule Set (CRS)** WAF engine, calculates explainable threat scores with Shannon entropy and velocity heuristics, streams real-time telemetry to an interactive Kanban command center, and **actively blocks contained attacker IPs (`HTTP 403 Forbidden`)** in real time.

---

## 1. Key Highlights & Architectural Identity

* **Dual-Layer Inspection Architecture:**
  * **Layer 1: Official OWASP Core Rule Set (CRS v4.30.0 / ModSecurity v3.0.17)** running inside an official Nginx reverse proxy via Docker Desktop on port 8080. Actively enforces HTTP 403 Forbidden blocking for attacks exceeding the inbound anomaly threshold (`ANOMALY_INBOUND=5`).
  * **Layer 2: Aapki Nazar Novelty & Heuristic Sensor** running in-process on Node.js (port 3001) evaluating multi-pass URL decoding, Shannon entropy ($H > 5.8$), and sliding-window velocity metrics.
* **Harmless Protected Demo Application:** Runs inside the isolated Docker network (`aapki-nazar-net`). All traffic to the demo service must traverse the ModSecurity WAF reverse proxy (direct host bypass port 3002 is closed).
* **Real-time Tail Ingestion Engine (`crsIngestionService.js`):** Continuously tails ModSecurity's serial JSON audit log (`./waf-logs/audit.log`) tracking byte offsets with chunked-line buffering, deduplicating transaction IDs, and mapping rules to the MITRE ATT&CK Framework.
* **Strict Incident Creation Policy:**
  * Protocol warnings on benign requests (`HTTP 200 OK`) are logged in `waf_events` without cluttering the incident command triage board.
  * Confirmed blocks (`HTTP 403 Forbidden`) and high-severity exploit signatures (`942` SQLi, `941` XSS, `932` RCE, `930` LFI) automatically generate actionable SOC incidents.
* **Real Active SOAR Defense (The Real 403 Block):**
  * When an analyst clicks **"Execute Active 403 Containment"** on the dashboard, the attacker's IP is added to the active gateway firewall blacklist.
  * The attacker's subsequent requests receive an immediate **`HTTP 403 Forbidden: Access Denied: Your IP address has been contained by Aapki Nazar SOC`** in under 15ms.
* **Live Attacker CLI Cyber Range (`attack.js`):** A standalone, zero-dependency Node.js attack tool supporting `--target crs` (Port 8080) and `--target soc` (Port 3001) for live demonstrations.

---

## 2. Platform Architecture Diagram

```
[Attacker Terminal (attack.js) / Browser / API Clients]
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 1. ACTIVE GATEWAY FIREWALL MIDDLEWARE (Port 3001)       │
│    - Active Blacklist Filter: Drops contained IPs (403) │
│    - Latency: < 15ms response                          │
└──────────────────────────┬─────────────────────────────┘
                           │ (Permitted IP)
                           ▼
┌────────────────────────────────────────────────────────┐
│ 2. OWASP WAF SENSOR (OWASP Core Rule Set CRS)          │
│    - 942100: SQL Injection (Union, Blind, Sleep)       │
│    - 941100: Cross-Site Scripting (XSS, DOM, scripts)  │
│    - 932100: Remote Command Injection (CMDi, Shell)    │
│    - 934100: Server-Side Request Forgery (SSRF)        │
│    - 930100: Path Traversal & LFI (../, /etc/passwd)   │
│    - 944100: Log4Shell & JNDI Remote Code Probes       │
└──────────────────────────┬─────────────────────────────┘
                           │ (Security Alert Event)
                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. AAPKI NAZAR SOC INTELLIGENCE BRAIN                  │
│    - Multi-Pass URL Decoding (2 levels deep)           │
│    - Shannon Entropy Obfuscation Engine (H > 5.8)      │
│    - 10-Second Sliding-Window IP Velocity Tracker      │
│    - Composite Threat Risk Scoring (0 - 100)           │
│    - 15-Minute Correlation & Deduplication Cache       │
│    - MITRE ATT&CK Framework Auto-Classifier           │
└──────────────────────────┬─────────────────────────────┘
                           │ (WebSocket Push)
                           ▼
┌────────────────────────────────────────────────────────┐
│ 4. INCIDENT COMMAND CENTER (The Kanban Dashboard)      │
│    - Real-Time WebSocket stream (Socket.io)            │
│    - Interactive Kanban Board (OPEN -> IN PROGRESS)    │
│    - War Room Modal with Code Fix & Forensics          │
│    - Active Gateway Blacklist Manager (with Unblock)   │
└──────────────────────────┬─────────────────────────────┘
                           │ (Analyst clicks "Execute Containment")
                           ▼
┌────────────────────────────────────────────────────────┐
│ 5. ACTIVE SOAR GATEWAY CONTAINMENT (REAL 403 BLOCK)    │
│    - Attacker IP added to Active Gateway Blacklist     │
│    - Attacker's next request receives HTTP 403!        │
└────────────────────────────────────────────────────────┘
```

---

## 3. Live Attacker CLI Cyber Range (`attack.js`)

Aapki Nazar includes a standalone command-line cyber range tool to demonstrate the full attack, detection, and active containment lifecycle.

```bash
# Benign Traffic (Baseline)
node attack.js --type clean

# Exploit Probes
node attack.js --type sqli          # SQL Injection (OWASP-CRS-942100)
node attack.js --type xss           # Cross-Site Scripting (OWASP-CRS-941100)
node attack.js --type cmdi          # Command Injection (OWASP-CRS-932100)
node attack.js --type log4j         # Log4Shell RCE (OWASP-CRS-944100)
node attack.js --type ssrf          # Cloud Metadata SSRF (OWASP-CRS-934100)
node attack.js --type lfi           # Path Traversal (OWASP-CRS-930100)
node attack.js --type bruteforce    # 36 Rapid Requests Velocity Spike

# Full Automated Suite
node attack.js --all
```

---

## 4. The Review Demonstration Walkthrough (Step-by-Step)

For your faculty or panel review, set up a **side-by-side split screen**:
* **Left Screen:** Terminal with `node attack.js`
* **Right Screen:** Browser with `http://localhost:3001`

### Step 1: Normal Traffic Baseline
1. In the terminal, run: `node attack.js --type clean`
2. **Terminal:** Prints `[CLEAN TRAFFIC] HTTP 200 OK`.
3. **Dashboard:** Live terminal stream displays a green `[CLEAN TRAFFIC] 200 OK` entry. No incident tickets created.

### Step 2: Live Exploit Injection
1. In the terminal, run: `node attack.js --type sqli`
2. **Terminal:** Shows latency (20ms) and indicates `[ALERT] OWASP WAF ALERT TRIGGERED! Ticket Created`.
3. **Dashboard:** Telemetry stream logs a red `[OWASP WAF ALERT] OWASP-CRS-942100: SQL Injection from 127.0.0.1` and automatically moves a new incident card into the `OPEN` Kanban column.

### Step 3: SOC Triage & Root Cause Analysis
1. On the dashboard, click on the newly created incident ticket.
2. Show the faculty:
   * **OWASP CRS Rule ID:** `OWASP-CRS-942100`
   * **MITRE ATT&CK Mapping:** `T1190: Exploit Public-Facing Application`
   * **Threat Risk Score:** 75/100 (HIGH)
   * **Extracted Exploit Payload:** `' UNION SELECT null, username, password FROM users...`
   * **Code Remediation:** Parameterized queries example.

### Step 4: Autonomous SOAR Containment (The Climax)
1. Click **"Execute Active 403 Containment (127.0.0.1)"**.
2. The ticket automatically moves to `RESOLVED`, an audit comment is appended, and the IP is registered in the active gateway blacklist.
3. Show the **"Gateway Blacklist (1)"** button in the top bar.

### Step 5: Active Defense Verification
1. In the attacker terminal, re-run: `node attack.js --type sqli`
2. **Terminal:** Immediately receives:
   ```text
   HTTP Status Code: 403 FORBIDDEN
   [CONTAINED] ACTIVE SOAR GATEWAY CONTAINMENT ENFORCED!
   Server Response: Access Denied: Your IP address has been contained by Aapki Nazar SOC.
   Contained IP:    127.0.0.1
   [CONFIRMED] Active Defense Proven: Attacker is completely locked out of the network.
   ```
3. **Dashboard:** Telemetry logs an amber `[GATEWAY 403 BLOCK] Dropped request from contained IP 127.0.0.1`.

### Step 6: Restoration of Service (Unblock)
1. Click **Gateway Blacklist** in the top bar.
2. Click **"Release / Unblock"** next to `127.0.0.1`.
3. Re-run `node attack.js --type clean` $\rightarrow$ Access is restored (`HTTP 200 OK`).

---

## 5. Installation & Setup

### Prerequisites
* **Node.js:** v18.x or higher installed.

### Quick Start
```bash
# 1. Install dependencies
npm install

# 2. Start Official OWASP CRS Gateway & Protected Demo Service via Docker
docker compose up -d

# 3. Start the Aapki Nazar SOC application
npm start
```

Navigate to: **`http://localhost:3001`**

### Controlled Cyber Range Attack Testing
```bash
# Test benign request through CRS gateway (HTTP 200 OK)
node attack.js --target crs --type clean

# Test SQL Injection through CRS gateway (HTTP 403 Forbidden Drop)
node attack.js --target crs --type sqli

# Test Cross-Site Scripting through CRS gateway (HTTP 403 Forbidden Drop)
node attack.js --target crs --type xss

# Test Path Traversal / LFI through CRS gateway (HTTP 403 Forbidden Drop)
node attack.js --target crs --type lfi
```

### Reset Dashboard
To wipe incidents and reset the database to a clean 0-alert baseline:
```bash
npm run reset
```

---

## 6. API Reference Summary

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Health check & active sensor status (`OWASP-WAF-CRS-v3.3`) |
| `/api/waf/status` | `GET` | Returns CRS version, active rules list, and inspection stats |
| `/api/waf/test` | `POST` | Browser/API quick-trigger for simulated cyber range attacks |
| `/api/waf/products` | `GET` | Sample protected web route (inspects query parameters) |
| `/api/waf/login` | `POST` | Sample protected auth route (inspects POST body & headers) |
| `/api/containment/:incidentId/contain` | `POST` | Blacklists attacker IP and updates incident to `RESOLVED` |
| `/api/containment/:ip/release` | `POST` | Unblocks contained IP and restores network access |
| `/api/containment/blacklist` | `GET` | Lists all active blacklisted IPs with metadata |
| `/incidents` | `GET/POST` | Manages incident tickets on the Kanban board |
| `/dashboard` | `GET` | Aggregated SOC operational analytics and metrics |

---

## License
MIT License. Built for cybersecurity education, research, and technical project demonstrations.
