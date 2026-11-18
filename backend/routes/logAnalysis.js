const express = require("express");
const incidentService = require("../services/incidentService");
const logAnalysisService = require("../services/logAnalysisService");

const router = express.Router();
const recentIncidentsByIp = new Map();

router.post("/", async (req, res) => {
  const logs = typeof req.body.logs === "string" ? req.body.logs.trim() : "";

  if (!logs) {
    return res.status(400).json({ error: "logs field is required and cannot be empty" });
  }

  try {
    const detection = await logAnalysisService.analyzeLogs(logs);
    let incident = null;

    if (detection.status === "threat_detected") {
      const matchedRules = Array.isArray(detection.matchedRules) ? detection.matchedRules : [];
      const matchedSummary = matchedRules
        .map((rule) => `${rule.id || rule.pattern} (${rule.type})`)
        .join(", ") || "none";

      const description = `Automated threat detection trigger. Type: ${detection.type}. Severity: ${detection.severity}. Threat Score: ${detection.threatScore}/100. Matched rules: ${matchedSummary}. Log snippet: ${logs
        .slice(0, 200)
        .replace(/\s+/g, " ")
        .trim()}${logs.length > 200 ? "..." : ""}`;

      const sourceIp = detection.normalizedLog?.sourceIp || "unknown";

      if (sourceIp !== "unknown") {
        const existingIncidentId = recentIncidentsByIp.get(sourceIp);
        if (existingIncidentId) {
          try {
            await incidentService.addComment(existingIncidentId, {
              note: `[CORRELATION] Repeated attack blocked from this IP. Threat: ${detection.type}. Score: ${detection.threatScore}`,
              author: "SOC-Engine"
            });
            if (req.io) req.io.emit("incident_updated", { incidentId: existingIncidentId });
            return res.json({ detection, incident: { incidentId: existingIncidentId, status: "correlated" } });
          } catch (e) {
            // If the incident was deleted, ignore and create a new one
            recentIncidentsByIp.delete(sourceIp);
          }
        }
      }

      incident = await incidentService.createIncident({
        title: `${detection.type || "Detected Threat"}${matchedRules[0]?.id ? ` (${matchedRules[0].id})` : ""}`,
        severity: detection.severity || "MEDIUM",
        status: "OPEN",
        assignedTo: "SOC-Engine",
        description,
        threatType: detection.type || "General Security Incident",
        mitreTechnique: detection.mitre ? [detection.mitre.id] : null,
        extractedPayload: detection.extractedPayload || null,
        playbook: detection.playbook || null,
        rootCause: detection.playbook?.rootCause || null,
        payload: detection.forensicPackage || null,
        confidence: detection.confidence || null
      });

      if (sourceIp !== "unknown") {
        recentIncidentsByIp.set(sourceIp, incident.incidentId);
        setTimeout(() => recentIncidentsByIp.delete(sourceIp), 15 * 60 * 1000);
      }

      if (req.io) {
        req.io.emit("incident_created", incident);
        req.io.emit("dashboard_update_needed");
      }
    }

    return res.json({
      detection,
      incident
    });
  } catch (err) {
    console.error("❌ Log analysis failed:", err.message);
    return res.status(500).json({ error: err.message || "Unable to analyze logs" });
  }
});

module.exports = router;
