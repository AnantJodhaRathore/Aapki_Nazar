const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });

const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");

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

const rateLimit = require("express-rate-limit");

// Middleware
const corsOptions = {
  origin: process.env.ALLOWED_ORIGIN || "*"
};
app.use(cors(corsOptions));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "../frontend")));

// Request Logging
app.use((req, res, next) => {
  if (!req.path.startsWith("/simulator/status")) {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  }
  next();
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ message: "Sentinel SOC API running with WebSockets & SQLite", status: "healthy" });
});

// Routes
const incidentsRoutes = require("./routes/incidents");
const dashboardRoutes = require("./routes/dashboard");
const logAnalysisRoutes = require("./routes/logAnalysis");
const simulatorRoutes = require("./routes/simulator");
const containmentRoutes = require("./routes/containment");
const rulesRoutes = require("./routes/rules");

const incidentsLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
const analyzeLogsLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
const simulatorLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
const containmentLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });

app.use("/incidents", incidentsLimiter, incidentsRoutes);
app.use("/dashboard", dashboardRoutes);
app.use("/analyze-logs", analyzeLogsLimiter, logAnalysisRoutes);
app.use("/api/simulator", simulatorLimiter, simulatorRoutes);
app.use("/api/containment", containmentLimiter, containmentRoutes);
app.use("/api/rules", rulesRoutes);

// Catch-all 404
app.use((req, res) => {
  res.status(404).json({
    message: "Not Found",
    requestedPath: req.path
  });
});

// Socket.io Connection Logic
io.on("connection", (socket) => {
  console.log(`🔌 Client connected: ${socket.id}`);
  socket.on("disconnect", () => {
    console.log(`🔌 Client disconnected: ${socket.id}`);
  });
});

// Start local server
const basePort = parseInt(process.env.PORT, 10) || 3001;
const maxPort = basePort + 5;

function startLocalServer(port) {
  server.listen(port, "127.0.0.1", () => {
    console.log(`🚀 Aapki Nazar SOC System running locally at http://127.0.0.1:${port}`);
    console.log(`📡 Real-Time WebSockets & Chaos Engine ready`);
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