# AAPKI NAZAR: WEB APPLICATION SOC & AUTONOMOUS WAF DEFENSE PLATFORM
## Master Specification: OWASP Web Application Firewall (WAF) & Active Gateway Defense

---

## 1. Project Overview & Identity
**Aapki Nazar** is an **Automated Web Application Security Operations Center (SOC)** and SIEM platform focused exclusively on **Web and Application Layer Security (Layer 7 HTTP / APIs)**.

Instead of an internal simulator or raw packet/antivirus confusion, Aapki Nazar operates as an active **Web Application SOC Gateway**:
1. **Traffic Ingestion Gateway:** Intercepts live incoming HTTP requests, parameters, and payloads.
2. **Security Sensor:** **OWASP Web Application Firewall (WAF) Engine** evaluating requests against official **OWASP Core Rule Set (CRS v3.3/v4.0)** rules for SQLi, XSS, CMDi, SSRF, LFI, and Log4j.
3. **SOC Intelligence Core (Aapki Nazar Brain):**
   * Multi-pass URL decoding (2 levels deep).
   * Shannon Entropy calculation ($H > 5.8$) to detect packed shellcode.
   * 10-second sliding-window IP velocity cache to detect brute-force bots ($\ge 35$ reqs).
   * Composite Threat Risk Scoring (0–100).
   * Deduplication and attack chain correlation.
   * MITRE ATT&CK technique mapping (`T1190`, `T1059`, `T1110`, etc.).
4. **Real Active SOAR Defense (The Real Firewall Block):**
   * When an analyst clicks **"Execute Containment"**, the IP is blacklisted at the active gateway.
   * The attacker's subsequent requests receive an immediate **`HTTP 403 Forbidden: IP Contained by Aapki Nazar SOC`**.
5. **Live Attacker CLI Cyber Range (`attack.js`):**
   * A command-line attack script (`node attack.js --type sqli|log4j|xss|bruteforce`) for split-screen faculty reviews.

---

## 2. Component Architecture Diagram

```
[Attacker Terminal (attack.js) / Browser / API Clients]
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 1. AAPKI NAZAR ACTIVE GATEWAY (Port 3001)              │
│    - Active Blacklist Filter: Drops contained IPs (403)│
│    - Intercepts incoming URLs, query params, headers   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 2. OWASP WAF ENGINE (OWASP Core Rule Set CRS)          │
│    - 942xxx: SQL Injection (Union, Blind, Sleep)       │
│    - 941xxx: Cross-Site Scripting (XSS, DOM, scripts)  │
│    - 932xxx: Remote Command Injection (CMDi, Shell)    │
│    - 934xxx: Server-Side Request Forgery (SSRF)        │
│    - 930xxx: Path Traversal & LFI (../, /etc/passwd)   │
│    - 944xxx: Log4Shell & JNDI Exploit Probes           │
└──────────────────────────┬─────────────────────────────┘
                           │ (WAF Security Alert Event)
                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. AAPKI NAZAR SOC INTELLIGENCE BRAIN                  │
│    - Shannon Entropy Obfuscation Engine (H > 5.8)      │
│    - 10-Second Sliding-Window IP Velocity Tracker      │
│    - Composite Threat Risk Scoring (0 - 100)           │
│    - Deduplication & Correlation Cache (15 min window) │
│    - MITRE ATT&CK Framework Auto-Classifier           │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 4. INCIDENT COMMAND CENTER (The Kanban Dashboard)      │
│    - Real-Time WebSocket stream (Socket.io)            │
│    - Interactive Kanban Board (OPEN -> PROGRESS -> RES)│
│    - SLA Timers & Background Escalation Service        │
│    - War Room Modal showing attack string & code fix   │
│    - SQLite Persistence (WAL mode)                     │
└──────────────────────────┬─────────────────────────────┘
                           │ (Analyst clicks "Execute Containment")
                           ▼
┌────────────────────────────────────────────────────────┐
│ 5. ACTIVE SOAR GATEWAY CONTAINMENT (REAL 403 BLOCK)    │
│    - Attacker's IP added to Active Gateway Blacklist   │
│    - Attacker's next request receives:                 │
│      "HTTP 403 Forbidden: IP Contained by SOC"         │
└────────────────────────────────────────────────────────┘
```

---

## 3. What We Will Do (Component-by-Component)

### 3.1 Clean Up Unwanted Artifacts
* Remove ClamAV artifacts (`backend/routes/clamav.js`, `backend/services/clamavAdapter.js`, `scripts/demo_clamav.js`).
* Remove Suricata PCAP artifacts (`backend/routes/suricata.js`, `backend/services/suricataAdapter.js`, `scripts/demo_suricata.js`).
* Remove `/api/clamav` and `/api/suricata` from `backend/server.js`.

### 3.2 Build the Inbound Gateway & Active 403 Firewall Middleware
* File: `backend/services/containmentService.js` & `backend/routes/containment.js`:
  * Manage active blacklist: `Set<string>` of contained IPs.
  * Middleware on all routes:
    ```javascript
    app.use((req, res, next) => {
      const clientIp = req.ip || req.connection.remoteAddress || "127.0.0.1";
      if (containmentService.isIpBlocked(clientIp)) {
        return res.status(403).json({
          error: "HTTP 403 Forbidden",
          message: "Access Denied: Your IP has been contained by Aapki Nazar SOC.",
          clientIp
        });
      }
      next();
    });
    ```
  * Real containment: When an analyst clicks "Execute Containment", the IP is added to the blacklist!
  * Real release: When resolved or unblocked, access is restored!

### 3.3 Build the Native OWASP WAF Engine (`backend/services/wafService.js`)
* Implements official OWASP Core Rule Set (CRS) inspection:
  * Analyzes request path, query string, headers, and body.
  * Rules:
    * `OWASP-CRS-942100`: SQL Injection
    * `OWASP-CRS-941100`: XSS Injection
    * `OWASP-CRS-932100`: Remote Command Injection (CMDi)
    * `OWASP-CRS-934100`: Server-Side Request Forgery (SSRF)
    * `OWASP-CRS-930100`: Path Traversal / LFI
    * `OWASP-CRS-944100`: Log4Shell & JNDI Probes
  * Output: Structured WAF event with Rule ID, severity, matched data, and threat score.
  * Bridges directly into `incidentService.createIncident()` and emits live WebSocket alerts.

### 3.4 Build the Live Attacker CLI & Cyber Range Tool (`attack.js`)
* Standalone script in project root:
  * `node attack.js --type sqli`
  * `node attack.js --type xss`
  * `node attack.js --type cmdi`
  * `node attack.js --type log4j`
  * `node attack.js --type ssrf`
  * `node attack.js --type bruteforce`
  * `node attack.js --type clean`
* Allows live demonstration of the full cycle: Attack $\rightarrow$ Detection $\rightarrow$ Ticket $\rightarrow$ Containment $\rightarrow$ 403 Block!

### 3.5 Frontend UI Polish
* Top-bar sensor badge: `● OWASP WAF ENGINE: ACTIVE (CRS v3.3)`
* Attack trigger buttons on the dashboard for instant browser-based testing.
* Color-coded terminal stream:
  * Red: `[OWASP WAF ALERT] Rule 942100: SQLi from 127.0.0.1`
  * Green: `[CLEAN TRAFFIC] GET /api/products (200 OK)`
  * Crimson/Yellow: `[GATEWAY BLOCK] HTTP 403 Forbidden for Contained IP 127.0.0.1`
* War Room modal showing exact OWASP Rule ID, MITRE technique (`T1190`), and real-time containment status.

---

## 4. The Review Demonstration (Step-by-Step)

1. Open two windows side-by-side:
   * Left: Attacker terminal (`node attack.js --type sqli`).
   * Right: Aapki Nazar SOC Dashboard (`http://localhost:3001`).
2. Run clean request $\rightarrow$ Dashboard displays green `[CLEAN] 200 OK`.
3. Launch attack $\rightarrow$ Dashboard displays red `[OWASP WAF ALERT]` and creates `HIGH` ticket on Kanban board.
4. Click ticket $\rightarrow$ Show OWASP Rule ID, raw attack string, and code fix.
5. Click **"Execute Containment"** $\rightarrow$ Moves to `RESOLVED` and adds IP to edge firewall.
6. Run attack again in attacker terminal $\rightarrow$ Receives `HTTP 403 Forbidden: IP Contained by Aapki Nazar SOC`!
