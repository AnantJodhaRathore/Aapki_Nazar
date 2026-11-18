const express = require("express");
const db = require("../services/localDbService");
const { computeHealthScore } = require("../utils/healthScore");
const escalationService = require("../services/escalationService");
const wafService = require("../services/wafService");
const containmentService = require("../services/containmentService");
const simulatorService = require("../services/simulatorService");
const crsIngestionService = require("../services/crsIngestionService");

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

    // Calculate Active MITRE ATT&CK Technique Counts
    const mitreStats = {};
    for (const inc of incidents) {
      if (inc.status !== "RESOLVED") {
        let mitre = inc.mitreTechnique;
        if (typeof mitre === "string") {
          try { mitre = JSON.parse(mitre); } catch (e) {}
        }
        const tid = (mitre && typeof mitre === "object" && mitre.id) ? mitre.id : (typeof mitre === "string" && mitre ? mitre : null);
        if (tid) {
          mitreStats[tid] = (mitreStats[tid] || 0) + 1;
        }
      }
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
    const wafStatus = wafService.getStatus();
    const crsStatus = crsIngestionService.getStatus();
    const wafStats = await db.getWafStats();

    const summary = {
      total,
      open,
      inProgress,
      resolved,
      critical,
      severityBreakdown,
      statusBreakdown,
      attackTypeBreakdown,
      mitreStats,
      analytics: {
        mttrMinutes,
        detectionLatencyMs: null, // Hardcoded fictitious metric removed; true latency measured dynamically on real requests
        slaComplianceRate,
        threatsDetected: incidents.filter(i => i.assignedTo === "OWASP-WAF-Engine" || i.assignedTo === "OWASP-CRS-Engine" || i.assignedTo === "SOC-Engine" || i.assignedTo === "Autonomous-SOC").length,
        wafRulesCount: wafStatus.rulesCount,
        totalInspected: wafStatus.totalInspected,
        totalAlerts: wafStatus.totalAlerts,
        // Official OWASP CRS metrics (RelevantOnly audit logging)
        crsActive: crsStatus.gateway?.status === "ONLINE",
        crsGatewayStatus: crsStatus.gateway?.status || "UNKNOWN",
        crsGatewayUrl: crsStatus.gateway?.url || "http://localhost:8080",
        crsIngestionActive: crsStatus.ingestion?.active || false,
        crsStoredAuditEvents: wafStats.totalEvents,
        crsBlockedCount: wafStats.blocked || wafStats.totalBlocked,
        crsDetectionOnlyCount: wafStats.allowed || wafStats.totalAllowed,
        crsAuditLoggingMode: "RelevantOnly",
        crsEventsCount: wafStats.totalEvents,
        crsVersion: crsStatus.versions?.crsVersion || "OWASP_CRS/4.30.0",
        crsModsecVersion: crsStatus.versions?.modsecVersion || "ModSecurity v3.0.17"
      },
      healthScore,
      escalatedCount
    };
    return res.json(summary);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.post("/reset", async (req, res) => {
  try {
    const result = db.resetDatabase();
    wafService.reset();
    containmentService.clear();
    simulatorService.stopSimulator();
    simulatorService.resetCounters();
    crsIngestionService.processedTxIds.clear();

    if (req.io) {
      req.io.emit("system_reset");
      req.io.emit("dashboard_update_needed");
      req.io.emit("simulator_state_changed", { isRunning: false });
      req.io.emit("gateway_blacklist_updated", { action: "RESET", totalBlocked: 0 });
      req.io.emit("telemetry_stream", {
        id: `reset-${Date.now()}`,
        timestamp: new Date().toISOString(),
        raw: "[SYSTEM RESET] SOC baseline, threat telemetry, and gateway containment cleared.",
        sensor: "SYSTEM",
        sourceIp: "127.0.0.1",
        isThreat: false,
        threatType: "System Baseline Reset",
        threatScore: 0,
        severity: "CLEAN",
        color: "#10b981",
        stats: { totalGenerated: 0, threatsBlocked: 0 }
      });
    }

    return res.json({
      success: true,
      message: "Dashboard reset to fresh initial state. Database, WAF caches, containment blacklists, and simulator cleared.",
      result
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

module.exports = router;
