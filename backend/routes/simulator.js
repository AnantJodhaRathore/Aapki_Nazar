const express = require("express");
const simulatorService = require("../services/simulatorService");

const router = express.Router();

// GET /api/simulator/status
router.get("/status", (req, res) => {
  try {
    const status = simulatorService.getStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: "Failed to get simulator status", details: err.message });
  }
});

// POST /api/simulator/start
router.post("/start", (req, res) => {
  try {
    const result = simulatorService.startSimulator(req.io, req.body || {});
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to start simulator", details: err.message });
  }
});

// POST /api/simulator/stop
router.post("/stop", (req, res) => {
  try {
    const result = simulatorService.stopSimulator();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to stop simulator", details: err.message });
  }
});

// POST or PATCH /api/simulator/config - Live settings update without restart!
const handleConfigUpdate = (req, res) => {
  try {
    const result = simulatorService.updateConfig(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to update simulator configuration", details: err.message });
  }
};

router.post("/config", handleConfigUpdate);
router.patch("/config", handleConfigUpdate);

// POST /api/simulator/reset
router.post("/reset", (req, res) => {
  try {
    simulatorService.resetCounters();
    res.json({ success: true, message: "Simulator counters reset" });
  } catch (err) {
    res.status(500).json({ error: "Failed to reset counters", details: err.message });
  }
});

module.exports = router;
