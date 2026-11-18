const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });

const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const rateLimit = require("express-rate-limit");

const containmentService = require("./services/containmentService");
const wafService = require("./services/wafService");
const crsIngestionService = require("./services/crsIngestionService");
const attackCorrelationService = require("./services/attackCorrelationService");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// Expose io to routes
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Base Middlewares
const corsOptions = {
  origin: process.env.ALLOWED_ORIGIN || "*"
};
app.use(cors(corsOptions));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// ── 1. ACTIVE GATEWAY FIREWALL MIDDLEWARE (REAL 403 BLOCK) ──
app.use((req, res, next) => {
  // Allow essential management routes and socket connections
  if (
    req.path.startsWith("/socket.io") ||
    req.path === "/api/health" ||
    req.path.startsWith("/api/containment")
  ) {
    return next();
  }

  const clientIp = req.ip || req.connection?.remoteAddress || "127.0.0.1";
  if (containmentService.isIpBlocked(clientIp)) {
    const blockDetails = containmentService.getBlockDetails(clientIp);
    console.log(`[GATEWAY 403] Dropped request from contained IP: ${clientIp} (${req.method} ${req.originalUrl || req.url})`);

    if (req.io) {
      req.io.emit("telemetry_stream", {
        id: `block-${Date.now()}`,
        timestamp: new Date().toISOString(),
        raw: `[GATEWAY BLOCKED] HTTP 403 Forbidden for contained IP ${clientIp} on ${req.method} ${req.originalUrl || req.url}`,
        sensor: "GATEWAY-SOAR",
        severity: "CRITICAL",
        color: "#dc2626"
      });
    }

    return res.status(403).json({
      error: "HTTP 403 Forbidden",
      message: "Access Denied: Your IP address has been contained by Aapki Nazar SOC.",
      clientIp,
      containment: blockDetails
    });
  }
  next();
});

// Static assets (served if not blocked by gateway)
app.use(express.static(path.join(__dirname, "../frontend")));

// Request Logging
app.use((req, res, next) => {
  if (!req.path.startsWith("/socket.io")) {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl || req.url}`);
  }
  next();
});

// ── 2. INBOUND CUSTOM WAF ENGINE SENSOR MIDDLEWARE ──
app.use(async (req, res, next) => {
  // Explicitly skip SOC control-plane routes, management APIs, static assets, and sockets
  const isControlPlane = 
    req.path.startsWith("/socket.io") ||
    req.path.startsWith("/api/health") ||
    req.path.startsWith("/api/waf/test") ||
    req.path.startsWith("/api/waf/crs") ||
    req.path.startsWith("/api/campaigns") ||
    req.path.startsWith("/api/containment") ||
    req.path.startsWith("/dashboard") ||
    req.path.startsWith("/incidents") ||
    req.path.startsWith("/api/rules") ||
    req.path.startsWith("/api/simulator") ||
    req.path.startsWith("/analyze-logs") ||
    req.path.endsWith(".css") ||
    req.path.endsWith(".js") ||
    req.path.endsWith(".ico") ||
    req.path.endsWith(".html") ||
    req.path.endsWith(".png") ||
    req.path.endsWith(".svg");

  if (isControlPlane) {
    return next();
  }

  try {
    const inspection = wafService.inspectRequest(req);
    if (inspection.isThreat) {
      await wafService.handleWafAlert(inspection, req);
    }
  } catch (err) {
    console.error("[CUSTOM WAF INSPECTION ERROR]", err.message);
  }
  next();
});

// Health check
app.get("/api/health", async (req, res) => {
  const crsStatus = crsIngestionService.getStatus();
  res.json({
    message: "Aapki Nazar SOC API running with Official OWASP CRS & SQLite",
    status: "healthy",
    gateway: crsStatus.gateway,
    ingestion: crsStatus.ingestion,
    versions: crsStatus.versions,
    sensors: {
      officialCrs: {
        engine: "OWASP ModSecurity Core Rule Set (Docker Nginx)",
        crsVersion: crsStatus.versions.crsVersion,
        modsecVersion: crsStatus.versions.modsecVersion,
        nginxVersion: crsStatus.versions.nginxVersion,
        gatewayStatus: crsStatus.gateway.status,
        gatewayUrl: crsStatus.gateway.url,
        ingestionStatus: crsStatus.ingestion.active ? "ACTIVE" : "OFFLINE",
        storedAuditEvents: crsStatus.ingestion.totalIngested,
        confirmedBlocked: crsStatus.ingestion.totalBlocked
      },
      customSensor: {
        engine: "Aapki Nazar Custom Heuristic Sensor",
        status: "active"
      }
    },
    timestamp: new Date().toISOString()
  });
});

// Routes
const incidentsRoutes = require("./routes/incidents");
const dashboardRoutes = require("./routes/dashboard");
const containmentRoutes = require("./routes/containment");
const rulesRoutes = require("./routes/rules");
const wafRoutes = require("./routes/waf");
const simulatorRoutes = require("./routes/simulator");
const campaignsRoutes = require("./routes/campaigns");

const incidentsLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
const containmentLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });

app.use("/incidents", incidentsLimiter, incidentsRoutes);
app.use("/dashboard", dashboardRoutes);
app.use("/api/containment", containmentLimiter, containmentRoutes);
app.use("/api/rules", rulesRoutes);
app.use("/api/waf", wafRoutes);
app.use("/api/simulator", simulatorRoutes);
app.use("/api/campaigns", campaignsRoutes);

// Threat Studio Log Analyzer endpoint
app.post("/analyze-logs", (req, res) => {
  const { logs, log, text } = req.body;
  const raw = logs || log || text || "";
  const result = wafService.analyzeRawLog(raw);
  res.json(result);
});

// Error handling for malformed JSON payloads
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && (err.status === 400 || err.statusCode === 400) && 'body' in err) {
    return res.status(400).json({ error: "Bad Request: Malformed JSON payload", details: err.message });
  }
  next(err);
});

// Catch-all 404
app.use((req, res) => {
  res.status(404).json({
    message: "Not Found",
    requestedPath: req.path
  });
});

// Socket.io Connection Logic
io.on("connection", (socket) => {
  console.log(`[SOCKET] Client connected: ${socket.id}`);
  socket.on("disconnect", () => {
    console.log(`[SOCKET] Client disconnected: ${socket.id}`);
  });
});

// Start local server
const basePort = parseInt(process.env.PORT, 10) || 3001;
const maxPort = basePort + 5;

function startLocalServer(port) {
  server.listen(port, "127.0.0.1", () => {
    console.log(`[SERVER] Aapki Nazar SOC System running locally at http://127.0.0.1:${port}`);
    console.log(`[OFFICIAL CRS] Docker ModSecurity Gateway: http://localhost:8080`);
    console.log(`[CUSTOM SENSOR] Novelty Detection Engine: ACTIVE`);
    console.log(`[GATEWAY] Real-Time WebSockets & Active Gateway Defense Ready`);

    // Start genuine OWASP CRS audit log ingestion
    crsIngestionService.start(io);

    // Initial historical campaign correlation backfill from stored WAF events
    attackCorrelationService.setIo(io);
    attackCorrelationService.backfillFromWafEvents().catch(err => {
      console.warn("[CORRELATION] Startup backfill warning:", err.message);
    });
  }).on("error", (err) => {
    if (err.code === "EADDRINUSE" && port < maxPort) {
      console.warn(`Port ${port} is in use. Trying ${port + 1}...`);
      startLocalServer(port + 1);
    } else {
      console.error("Failed to start server:", err);
      process.exit(1);
    }
  });
}

startLocalServer(basePort);

const escalationService = require("./services/escalationService");

// Background SLA Escalation Check
setInterval(async () => {
  try {
    const escalatedCount = await escalationService.runEscalationCheck();
    if (escalatedCount > 0) {
      io.emit("dashboard_update_needed");
      io.emit("sla_escalation", { count: escalatedCount });
    }
  } catch (err) {
    console.error("Escalation check failed:", err);
  }
}, 60 * 1000); // every 60s

module.exports = { app, server, io };