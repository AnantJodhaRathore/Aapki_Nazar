const express = require("express");
const incidentService = require("../services/incidentService");

const router = express.Router();

// Export CSV
router.get("/export/csv", async (req, res) => {
  try {
    const incidents = await incidentService.getAllIncidents();
    const headers = [
      "Incident ID", 
      "Created At", 
      "Title", 
      "Severity", 
      "Status", 
      "Event Source",
      "WAF Transaction ID",
      "Assigned To", 
      "Threat Type",
      "MITRE ATT&CK",
      "Source IP",
      "Target Path",
      "Threat Score",
      "SLA Deadline",
      "Raw Log"
    ];
    
    const rows = incidents.map(inc => {
      let payloadObj = {};
      if (typeof inc.payload === 'string') {
        try { payloadObj = JSON.parse(inc.payload); } catch(e) {}
      } else if (inc.payload) {
        payloadObj = inc.payload;
      }
      
      const sourceIp = payloadObj.ip || payloadObj.sourceIp || payloadObj.normalizedLog?.sourceIp || "N/A";
      const targetPath = payloadObj.path || payloadObj.normalizedLog?.path || "N/A";
      const rawLog = payloadObj.rawLog || "";
      const threatScore = payloadObj.threatScore || (inc.description ? (inc.description.match(/Threat (?:Risk )?Score: (\d+)/)?.[1] || "N/A") : "N/A");
      let mitre = inc.mitreTechnique || "N/A";
      const eventSource = inc.eventSource || (inc.assignedTo === 'OWASP-CRS-Engine' ? 'OFFICIAL_CRS' : 'CUSTOM_WAF');
      const wafTxId = inc.wafTransactionId || payloadObj.transactionId || "N/A";

      return [
        `"${inc.incidentId || ''}"`,
        `"${inc.createdAt || ''}"`,
        `"${(inc.title || '').replace(/"/g, '""')}"`,
        `"${inc.severity || ''}"`,
        `"${inc.status || ''}"`,
        `"${eventSource}"`,
        `"${wafTxId}"`,
        `"${(inc.assignedTo || '').replace(/"/g, '""')}"`,
        `"${inc.threatType || ''}"`,
        `"${mitre.replace(/"/g, '""')}"`,
        `"${sourceIp}"`,
        `"${targetPath.replace(/"/g, '""')}"`,
        `"${threatScore}"`,
        `"${inc.slaDeadline || ''}"`,
        `"${rawLog.replace(/"/g, '""')}"`
      ];
    });

    const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="incidents_export_${Date.now()}.csv"`);
    res.status(200).send(csvContent);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/", async (req, res) => {
  try {
    const { severity, status, title, description } = req.body;
    
    // Validation
    const validSeverities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    if (severity && !validSeverities.includes(severity)) {
      return res.status(400).json({ error: "Invalid severity. Must be LOW, MEDIUM, HIGH, or CRITICAL." });
    }
    const validStatuses = ["OPEN", "IN_PROGRESS", "RESOLVED"];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid status. Must be OPEN, IN_PROGRESS, or RESOLVED." });
    }
    if (title && title.length > 255) return res.status(400).json({ error: "Title too long (max 255 chars)." });
    if (description && description.length > 5000) return res.status(400).json({ error: "Description too long (max 5000 chars)." });

    const result = await incidentService.createIncident(req.body);
    req.io.emit("incident_created", result);
    req.io.emit("dashboard_update_needed");
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/", async (req, res) => {
  try {
    const result = await incidentService.getAllIncidents(req.query);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const result = await incidentService.getIncidentById(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

router.put("/:id", async (req, res) => {
  try {
    const { severity, status } = req.body;
    const validSeverities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    if (severity && !validSeverities.includes(severity)) {
      return res.status(400).json({ error: "Invalid severity." });
    }
    const validStatuses = ["OPEN", "IN_PROGRESS", "RESOLVED"];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid status." });
    }

    const result = await incidentService.updateIncident(req.params.id, req.body);
    req.io.emit("incident_updated", result);
    req.io.emit("dashboard_update_needed");
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/:id/comments", async (req, res) => {
  try {
    const { text, author } = req.body;
    if (text && text.length > 2000) return res.status(400).json({ error: "Comment too long (max 2000 chars)." });
    if (author && author.length > 100) return res.status(400).json({ error: "Author name too long (max 100 chars)." });

    const result = await incidentService.addComment(req.params.id, req.body);
    req.io.emit("incident_updated", result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/:id/quick-action", async (req, res) => {
  try {
    const result = await incidentService.handleQuickAction(req.params.id, req.body);
    req.io.emit("incident_updated", result);
    req.io.emit("dashboard_update_needed");
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete("/:id", async (req, res) => {
  res.status(403).json({ error: "Incident deletion is disabled to preserve audit evidence. Use reset to clear database." });
});

module.exports = router;
