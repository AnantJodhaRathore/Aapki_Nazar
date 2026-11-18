const express = require("express");
const simulatorService = require("../services/simulatorService");

const router = express.Router();

router.get("/status", (req, res) => {
  res.json(simulatorService.getStatus());
});

router.post("/start", (req, res) => {
  let interval = parseInt(req.body.interval, 10) || 1500;
  interval = Math.max(100, Math.min(interval, 10000));
  let attackRatio = parseFloat(req.body.attackRatio);
  if (isNaN(attackRatio)) attackRatio = 0.35;
  attackRatio = Math.max(0, Math.min(attackRatio, 1));
  const result = simulatorService.startSimulator(req.io, interval, attackRatio);
  res.json(result);
});

router.post("/stop", (req, res) => {
  const result = simulatorService.stopSimulator();
  res.json(result);
});

router.post("/inject-single", (req, res) => {
  const sample = simulatorService.generateSingleLog();
  res.json(sample);
});

module.exports = router;
