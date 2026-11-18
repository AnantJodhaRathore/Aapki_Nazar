/**
 * Aapki Nazar - Attack Campaigns REST API (Phase 2)
 * 
 * Provides endpoints for retrieving correlated attack campaigns, chronological event timelines,
 * 5-factor explainable threat prioritization, aggregated SOC metrics, and historical backfill.
 */

const express = require("express");
const router = express.Router();
const localDb = require("../services/localDbService");
const attackCorrelationService = require("../services/attackCorrelationService");

/**
 * GET /api/campaigns/stats
 * Aggregated campaign metrics & raw event reduction statistics
 */
router.get("/stats", async (req, res) => {
  try {
    const stats = await localDb.getCampaignStats();
    res.json(stats);
  } catch (err) {
    console.error("[CAMPAIGNS-API] Error fetching stats:", err.message);
    res.status(500).json({ error: "Failed to retrieve campaign statistics", details: err.message });
  }
});

/**
 * GET /api/campaigns/quarantine
 * Retrieve quarantined audit log records that failed parsing
 */
router.get("/quarantine", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 100;
    const records = await localDb.getQuarantineRecords(limit);
    res.json({
      count: records.length,
      quarantinedRecords: records
    });
  } catch (err) {
    console.error("[CAMPAIGNS-API] Error fetching quarantine:", err.message);
    res.status(500).json({ error: "Failed to retrieve quarantine records", details: err.message });
  }
});

/**
 * GET /api/campaigns
 * List correlated attack campaigns with optional filtering
 * Query params: ?status=ACTIVE&riskLevel=CRITICAL&limit=50
 */
router.get("/", async (req, res) => {
  try {
    const filters = {
      status: req.query.status || undefined,
      riskLevel: req.query.riskLevel ? req.query.riskLevel.toUpperCase() : undefined,
      identityType: req.query.identityType ? req.query.identityType.toUpperCase() : undefined,
      limit: req.query.limit ? parseInt(req.query.limit, 10) : 100
    };

    const campaigns = await localDb.getAllCampaigns(filters);
    res.json({
      count: campaigns.length,
      filters,
      campaigns
    });
  } catch (err) {
    console.error("[CAMPAIGNS-API] Error fetching campaigns:", err.message);
    res.status(500).json({ error: "Failed to retrieve campaigns", details: err.message });
  }
});

/**
 * GET /api/campaigns/:id
 * Retrieve a single attack campaign by ID
 */
router.get("/:id", async (req, res) => {
  try {
    const campaign = await localDb.getCampaignById(req.params.id);
    if (!campaign) {
      return res.status(404).json({ error: "Campaign not found", campaignId: req.params.id });
    }
    res.json(campaign);
  } catch (err) {
    console.error(`[CAMPAIGNS-API] Error fetching campaign ${req.params.id}:`, err.message);
    res.status(500).json({ error: "Failed to retrieve campaign", details: err.message });
  }
});

/**
 * GET /api/campaigns/:id/events
 * Retrieve the chronological attack sequence timeline for a campaign
 */
router.get("/:id/events", async (req, res) => {
  try {
    const campaign = await localDb.getCampaignById(req.params.id);
    if (!campaign) {
      return res.status(404).json({ error: "Campaign not found", campaignId: req.params.id });
    }

    const events = await localDb.getCampaignEvents(req.params.id);
    res.json({
      campaignId: req.params.id,
      count: events.length,
      timeline: events
    });
  } catch (err) {
    console.error(`[CAMPAIGNS-API] Error fetching events for campaign ${req.params.id}:`, err.message);
    res.status(500).json({ error: "Failed to retrieve campaign events", details: err.message });
  }
});

/**
 * GET /api/campaigns/:id/explanation
 * Retrieve the 5-factor explainable threat prioritization breakdown
 */
router.get("/:id/explanation", async (req, res) => {
  try {
    const explanation = await localDb.getCampaignRiskExplanation(req.params.id);
    if (!explanation) {
      return res.status(404).json({ error: "Explanation not found for campaign", campaignId: req.params.id });
    }
    res.json(explanation);
  } catch (err) {
    console.error(`[CAMPAIGNS-API] Error fetching explanation for campaign ${req.params.id}:`, err.message);
    res.status(500).json({ error: "Failed to retrieve campaign explanation", details: err.message });
  }
});

/**
 * PATCH /api/campaigns/:id/status
 * Update status of a campaign (e.g. ACTIVE -> MITIGATED or CLOSED)
 */
router.patch("/:id/status", async (req, res) => {
  try {
    const { status } = req.body;
    if (!status || !["ACTIVE", "MITIGATED", "CLOSED"].includes(status.toUpperCase())) {
      return res.status(400).json({ error: "Invalid status. Allowed values: ACTIVE, MITIGATED, CLOSED" });
    }

    const updated = await localDb.updateCampaign(req.params.id, { status: status.toUpperCase() });
    if (!updated) {
      return res.status(404).json({ error: "Campaign not found" });
    }

    if (req.io) {
      req.io.emit("campaign_updated", updated);
    }

    res.json(updated);
  } catch (err) {
    console.error(`[CAMPAIGNS-API] Error updating campaign status ${req.params.id}:`, err.message);
    res.status(500).json({ error: "Failed to update campaign status", details: err.message });
  }
});

/**
 * POST /api/campaigns/backfill
 * Idempotent historical backfill of existing WAF events into campaigns
 */
router.post("/backfill", async (req, res) => {
  try {
    const result = await attackCorrelationService.backfillFromWafEvents();
    if (req.io) {
      req.io.emit("dashboard_update_needed");
    }
    res.json({
      success: true,
      message: `Historical backfill completed. Correlated ${result.processedEvents} WAF events.`,
      ...result
    });
  } catch (err) {
    console.error("[CAMPAIGNS-API] Backfill failed:", err.message);
    res.status(500).json({ error: "Backfill failed", details: err.message });
  }
});

/**
 * POST /api/campaigns/recover
 * Recover any unlinked eligible events into campaigns
 */
router.post("/recover", async (req, res) => {
  try {
    const result = await localDb.reconcileMissingEligibleEvents();
    if (req.io) {
      req.io.emit("dashboard_update_needed");
    }
    res.json({
      success: true,
      message: `Recovery completed. Correlated ${result.linkedEventsCount} eligible events across ${result.campaignsCount} campaigns.`,
      ...result
    });
  } catch (err) {
    console.error("[CAMPAIGNS-API] Recovery failed:", err.message);
    res.status(500).json({ error: "Recovery failed", details: err.message });
  }
});

module.exports = router;

