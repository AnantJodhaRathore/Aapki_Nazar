const express = require("express");
const incidentService = require("../services/incidentService");

const router = express.Router();
const containedIps = new Set();

router.post("/:incidentId/contain", async (req, res) => {
  const { incidentId } = req.params;
  const { ip } = req.body;

  if (!ip) return res.status(400).json({ error: "IP address required" });

  containedIps.add(ip);
  
  await incidentService.addComment(incidentId, {
    note: `[SOAR SIMULATION] Executed containment playbook. IP ${ip} blocked at edge firewall.`,
    author: "SOAR-Bot"
  });

  if (req.io) {
    req.io.emit("incident_updated", { incidentId });
  }

  res.json({ message: "Containment successful", ip });
});

module.exports = router;
