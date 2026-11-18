const express = require("express");
const db = require("../services/localDbService");
const { computeHealthScore } = require("../utils/healthScore");
const escalationService = require("../services/escalationService");
const logAnalysisService = require("../services/logAnalysisService");

const router = express.Router();

router.get("/", async (req, res) => {
  try {
    const escalatedCount = await escalationService.runEscalationCheck();
    const incidents = await db.getAllIncidents();

    const total = incidents.length;
    const open = incidents.filter((i) => i.status === "OPEN").length;
    const inProgress = incidents.filter((i) => i.status === "IN_PROGRESS").length;
    const resolved = incidents.filter((i) => i.status === "RESOLVED").length;
    const critical = incidents.filter(
      (i) => i.severity === "CRITICAL" && i.status !== "RESOLVED"
    ).length;

    const severityBreakdown = {
      LOW: incidents.filter((i) => i.severity === "LOW" && i.status !== "RESOLVED").length,
      MEDIUM: incidents.filter((i) => i.severity === "MEDIUM" && i.status !== "RESOLVED").length,
      HIGH: incidents.filter((i) => i.severity === "HIGH" && i.status !== "RESOLVED").length,
      CRITICAL: incidents.filter((i) => i.severity === "CRITICAL" && i.status !== "RESOLVED").length
    };

    const statusBreakdown = {
      OPEN: open,
      IN_PROGRESS: inProgress,
      RESOLVED: resolved
    };

    // Calculate Attack Type Breakdown for Donut Chart
    const attackTypeBreakdown = {};
    for (const inc of incidents) {
      let type = inc.threatType || "General Operational";
      attackTypeBreakdown[type] = (attackTypeBreakdown[type] || 0) + 1;
    }

    // Calculate MTTR (Mean Time to Resolve in Minutes) & SLA Compliance Rate
    let totalResolveTimeMs = 0;
    let resolvedCount = 0;
    let slaMetCount = 0;

    for (const inc of incidents) {
      if (inc.status === "RESOLVED") {
        resolvedCount++;
        const created = new Date(inc.createdAt).getTime();
        const resolved = inc.resolvedAt ? new Date(inc.resolvedAt).getTime() : new Date(inc.updatedAt).getTime();
        const diff = Math.max(1, resolved - created);
        totalResolveTimeMs += diff;

        if (inc.slaDeadline) {
          const deadline = new Date(inc.slaDeadline).getTime();
          if (resolved <= deadline) {
            slaMetCount++;
          }
        }
      }
    }

    const mttrMinutes = resolvedCount > 0 ? Math.round(totalResolveTimeMs / resolvedCount / (1000 * 60)) : "N/A";
    const slaComplianceRate = resolvedCount > 0 ? Math.round((slaMetCount / resolvedCount) * 100) : "N/A";

    const healthScore = computeHealthScore(incidents);

    const summary = {
      total,
      open,
      inProgress,
      resolved,
      critical,
      severityBreakdown,
      statusBreakdown,
      attackTypeBreakdown,
      analytics: {
        mttrMinutes,
        detectionLatencyMs: logAnalysisService.getAverageDetectionLatency() > 0 ? parseFloat(logAnalysisService.getAverageDetectionLatency().toFixed(4)) : "N/A",
        slaComplianceRate,
        threatsDetected: incidents.filter(i => i.assignedTo === "SOC-Engine" || i.assignedTo === "Autonomous-SOC").length
      },
      healthScore,
      escalatedCount
    };
    return res.json(summary);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

const simulatorService = require("../services/simulatorService");

router.post("/reset", async (req, res) => {
  try {
    const result = db.resetDatabase();
    simulatorService.resetCounters();
    return res.json({ success: true, message: "Dashboard reset to fresh initial state.", result });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

module.exports = router;
