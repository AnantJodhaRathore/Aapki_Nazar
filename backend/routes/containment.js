const express = require("express");
const incidentService = require("../services/incidentService");
const containmentService = require("../services/containmentService");

const router = express.Router();

// Direct IP containment (from Gateway Command Center or Blacklist Modal)
router.post("/block", (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) {
    return res.status(400).json({ error: "IP address is required for containment." });
  }

  const blockRecord = containmentService.blockIp(
    ip,
    reason || "Contained via Gateway Firewall Command",
    "MANUAL-GATEWAY",
    req.body.author || "SOC-Analyst"
  );

  if (req.io) {
    req.io.emit("gateway_blacklist_updated", {
      action: "BLOCK",
      ip: blockRecord.ip,
      totalBlocked: containmentService.getAllBlockedIps().length
    });
    req.io.emit("telemetry_stream", {
      id: `tel-${Date.now()}`,
      timestamp: new Date().toISOString(),
      raw: `[GATEWAY CONTAINMENT] IP ${blockRecord.ip} active blacklist enforced (HTTP 403)`,
      sensor: "GATEWAY-SOAR",
      sourceIp: blockRecord.ip,
      isThreat: true,
      threatType: "Gateway Firewall Blacklist",
      threatScore: 90,
      severity: "HIGH",
      color: "crimson",
      stats: { totalGenerated: 1, threatsBlocked: 1 }
    });
  }

  res.json({
    message: "Active containment executed successfully. Gateway dropping traffic with HTTP 403.",
    containment: blockRecord
  });
});

router.post("/contain", (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) {
    return res.status(400).json({ error: "IP address is required for containment." });
  }

  const blockRecord = containmentService.blockIp(
    ip,
    reason || "Contained via Gateway Command",
    "MANUAL-GATEWAY",
    req.body.author || "SOC-Analyst"
  );

  if (req.io) {
    req.io.emit("gateway_blacklist_updated", {
      action: "BLOCK",
      ip: blockRecord.ip,
      totalBlocked: containmentService.getAllBlockedIps().length
    });
    req.io.emit("telemetry_stream", {
      id: `tel-${Date.now()}`,
      timestamp: new Date().toISOString(),
      raw: `[GATEWAY CONTAINMENT] IP ${blockRecord.ip} active blacklist enforced (HTTP 403)`,
      sensor: "GATEWAY-SOAR",
      sourceIp: blockRecord.ip,
      isThreat: true,
      threatType: "Gateway Firewall Blacklist",
      threatScore: 90,
      severity: "HIGH",
      color: "crimson",
      stats: { totalGenerated: 1, threatsBlocked: 1 }
    });
  }

  res.json({
    message: "Active containment executed successfully. Gateway dropping traffic with HTTP 403.",
    containment: blockRecord
  });
});

// Contain an IP associated with an incident
router.post("/:incidentId/contain", async (req, res) => {
  const { incidentId } = req.params;
  const { ip, reason } = req.body;

  if (!ip) {
    return res.status(400).json({ error: "IP address is required for containment." });
  }

  const blockRecord = containmentService.blockIp(
    ip,
    reason || `Contained via Incident ${incidentId}`,
    incidentId,
    req.body.author || "SOC-Analyst"
  );

  try {
    await incidentService.addComment(incidentId, {
      note: `[ACTIVE GATEWAY DEFENSE] Executed containment playbook. IP ${blockRecord.ip} blacklisted at active gateway (HTTP 403 enforcement).`,
      author: req.body.author || "SOAR-ActiveDefense"
    });
    // Update incident status to RESOLVED
    await incidentService.updateIncident(incidentId, {
      status: "RESOLVED",
      resolution: `Attacker IP ${blockRecord.ip} contained at active gateway.`
    });
  } catch (err) {
    console.warn(`[CONTAINMENT] Note update for ${incidentId} skipped:`, err.message);
  }

  if (req.io) {
    req.io.emit("incident_updated", { incidentId, status: "RESOLVED" });
    req.io.emit("gateway_blacklist_updated", {
      action: "BLOCK",
      ip: blockRecord.ip,
      totalBlocked: containmentService.getAllBlockedIps().length
    });
    req.io.emit("telemetry_stream", {
      id: `tel-${Date.now()}`,
      timestamp: new Date().toISOString(),
      raw: `[GATEWAY CONTAINMENT] IP ${blockRecord.ip} active blacklist enforced (HTTP 403)`,
      sensor: "GATEWAY-SOAR",
      severity: "HIGH",
      color: "crimson"
    });
  }

  res.json({
    message: "Active containment executed successfully. Gateway dropping traffic with HTTP 403.",
    containment: blockRecord
  });
});

// Release an IP from the active blacklist
router.post("/:ip/release", (req, res) => {
  const { ip } = req.params;
  const released = containmentService.unblockIp(ip);

  if (req.io) {
    req.io.emit("gateway_blacklist_updated", {
      action: "UNBLOCK",
      ip,
      totalBlocked: containmentService.getAllBlockedIps().length
    });
    req.io.emit("telemetry_stream", {
      id: `tel-${Date.now()}`,
      timestamp: new Date().toISOString(),
      raw: `[GATEWAY UNBLOCK] IP ${ip} released from active blacklist. Access restored.`,
      sensor: "GATEWAY-SOAR",
      severity: "LOW",
      color: "green"
    });
  }

  res.json({
    message: released ? `IP ${ip} released from gateway blacklist.` : `IP ${ip} was not in blacklist.`,
    released,
    ip
  });
});

// List all active blacklisted IPs
router.get("/blacklist", (req, res) => {
  res.json({
    count: containmentService.getAllBlockedIps().length,
    blacklist: containmentService.getAllBlockedIps()
  });
});

module.exports = router;
