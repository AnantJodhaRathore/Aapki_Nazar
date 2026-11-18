/**
 * Aapki Nazar - Phase 2: Context-Aware Attack Correlation & Explainable Threat Prioritization
 * 
 * Aggregates isolated OWASP CRS events into coherent Attack Campaigns within a sliding 10-minute window.
 * Evaluates contextual risk across 5 explainable factors:
 *   Contextual Risk = 0.35 * Severity + 0.25 * Frequency + 0.20 * Diversity + 0.10 * Persistence + 0.10 * TargetSensitivity
 * 
 * Preserves strict separation between real network socket client IP and simulated test identities.
 * Enforces campaign idempotency, monotonic timestamp bounds, and clean filtering of benign protocol warnings.
 */

const localDb = require("./localDbService");
const incidentService = require("./incidentService");
const riskEngine = require("./contextualRiskEngine");

const WINDOW_MS = 10 * 60 * 1000; // 10-minute sliding window

class AttackCorrelationService {
  constructor() {
    this.io = null;
    this.windowMs = WINDOW_MS;
  }

  setIo(ioInstance) {
    this.io = ioInstance;
  }

  /**
   * Determine correlation identity and partitioning key.
   * Distinguishes real network IPs from simulation sessions.
   * If a simulation session ID is provided: SIM:<simIp>:<sessionId>
   * If only simulated IP is provided:      SIM:<simIp>:legacy
   * Otherwise:                             REAL:<netIp>
   */
  getIdentityAndKey(wafEvent) {
    if (wafEvent.simulatedClientIp && String(wafEvent.simulatedClientIp).trim() !== "") {
      const simIp = String(wafEvent.simulatedClientIp).trim();
      const sessId = wafEvent.simulatedSessionId ? String(wafEvent.simulatedSessionId).trim() : "legacy";
      return {
        identityType: "SIMULATION_SESSION",
        correlationKey: `SIM:${simIp}:${sessId}`,
        displayName: `${simIp} [Session: ${sessId}]`
      };
    }

    const netIp = String(wafEvent.clientIp || "127.0.0.1").trim();
    return {
      identityType: "REAL_NETWORK_IP",
      correlationKey: `REAL:${netIp}`,
      displayName: netIp
    };
  }

  /**
   * Authoritative delegates to single riskEngine module
   */
  getEndpointSensitivity(uri) {
    return riskEngine.getEndpointSensitivity(uri);
  }

  getEventSeverityScore(event) {
    return riskEngine.getEventSeverityScore(event);
  }

  calculateContextualRisk(events) {
    return riskEngine.calculateContextualRisk(events);
  }

  /**
   * Close active campaigns whose last activity exceeds the sliding window
   * Preserves MITIGATED campaigns.
   */
  async closeInactiveCampaigns(referenceTime = Date.now()) {
    const activeCampaigns = await localDb.getAllCampaigns({ status: "ACTIVE" });
    const refMs = typeof referenceTime === "number" ? referenceTime : new Date(referenceTime).getTime();
    let closedCount = 0;

    for (const camp of activeCampaigns) {
      const lastMs = new Date(camp.lastSeen).getTime();
      if (!isNaN(lastMs) && (refMs - lastMs) > this.windowMs) {
        await localDb.updateCampaign(camp.id, { status: "CLOSED" });
        closedCount++;
      }
    }

    return closedCount;
  }

  /**
   * Ingest and correlate an eligible WAF event into a campaign.
   * Enforces:
   *  1. Strict event eligibility (filters benign warnings like rule 920350 HTTP 200 score 0).
   *  2. Strict event idempotency (returns existing campaign if event was already linked).
   *  3. Monotonic timestamp boundaries (firstSeen <= lastSeen).
   *  4. 10-minute sliding window separation.
   */
  async processEvent(wafEvent, options = {}) {
    if (!wafEvent) return null;

    // 1. Strict Eligibility Filter: Benign protocol warnings without blocks or exploit anomaly do not form campaigns
    if (!localDb.isEventEligible(wafEvent)) {
      return { eligible: false, message: "Benign/background event excluded from attack campaign correlation." };
    }

    const eventId = wafEvent.id || wafEvent.transactionId;

    // 2. Event Idempotency Check: Check if event is ALREADY correlated in ANY campaign (ACTIVE, CLOSED, or MITIGATED)
    const existingCampaign = await localDb.getCampaignByWafEventId(eventId);
    if (existingCampaign) {
      return existingCampaign;
    }

    const eventTime = new Date(wafEvent.timestamp || wafEvent.createdAt || Date.now()).getTime();
    const eventIso = new Date(eventTime).toISOString();
    const { identityType, correlationKey, displayName } = this.getIdentityAndKey(wafEvent);

    // 3. Find an active campaign matching the correlation key
    let campaign = await localDb.getActiveCampaignByKey(correlationKey);
    let isNewCampaign = false;

    if (campaign) {
      const campaignLastSeen = new Date(campaign.lastSeen).getTime();
      const timeDiff = eventTime - campaignLastSeen;

      // If time difference exceeds sliding window (or is out of order beyond window), close old campaign
      if (timeDiff > this.windowMs) {
        await localDb.updateCampaign(campaign.id, { status: "CLOSED" });
        campaign = null;
      }
    }

    if (!campaign) {
      isNewCampaign = true;
      const initialEndpoints = wafEvent.uri ? [wafEvent.uri] : [];
      const derivedCat = wafEvent.category || localDb.deriveCategory(wafEvent);
      const initialCategories = derivedCat ? [derivedCat] : [];

      campaign = await localDb.createCampaign({
        correlationKey,
        identityType,
        firstSeen: eventIso,
        lastSeen: eventIso,
        status: "ACTIVE",
        eventCount: 1,
        blockedCount: wafEvent.blocked ? 1 : 0,
        riskScore: 0,
        riskLevel: "LOW",
        incidentId: wafEvent.incidentId || null,
        targetEndpoints: initialEndpoints,
        attackCategories: initialCategories
      });
    }

    // Retrieve all previously linked events for this campaign
    const existingEvents = await localDb.getCampaignEvents(campaign.id);
    const isAlreadyInList = existingEvents.some(e => e.wafEventId === eventId || e.transactionId === wafEvent.transactionId);

    const fullEventsList = [...existingEvents];
    if (!isAlreadyInList) {
      fullEventsList.push({
        ...wafEvent,
        category: wafEvent.category || localDb.deriveCategory(wafEvent),
        timestamp: eventIso
      });
    }

    // Recompute contextual risk across all events in campaign
    const metrics = this.calculateContextualRisk(fullEventsList);

    // If not yet linked, save to campaign_events table with unique constraint safety
    if (!isAlreadyInList) {
      await localDb.addCampaignEvent({
        campaignId: campaign.id,
        wafEventId: eventId,
        eventTimestamp: eventIso,
        riskScoreAfterEvent: metrics.riskScore
      });
    }

    // Aggregate unique endpoints, categories, and blocks
    const allEndpoints = Array.from(new Set(fullEventsList.map(e => e.uri).filter(Boolean)));
    const allCategories = Array.from(new Set(fullEventsList.map(e => e.category || localDb.deriveCategory(e)).filter(Boolean)));
    const blockedCount = fullEventsList.filter(e => e.blocked).length;

    // Preserve monotonic timestamp bounds
    const existingFirstSeen = new Date(campaign.firstSeen).getTime();
    const existingLastSeen = new Date(campaign.lastSeen).getTime();
    const monotonicFirstSeen = new Date(Math.min(existingFirstSeen, eventTime)).toISOString();
    const monotonicLastSeen = new Date(Math.max(existingLastSeen, eventTime)).toISOString();

    // Check incident linkage
    let linkedIncidentId = campaign.incidentId || wafEvent.incidentId || null;
    if (!linkedIncidentId) {
      const anyLinked = fullEventsList.find(e => e.incidentId);
      if (anyLinked) linkedIncidentId = anyLinked.incidentId;
    }

    // Escalate to incident if threshold met and not already created
    const previousRiskLevel = campaign.riskLevel;
    const isEscalation = (previousRiskLevel !== metrics.riskLevel) && 
                         (metrics.riskLevel === "HIGH" || metrics.riskLevel === "CRITICAL");

    if (isEscalation && !linkedIncidentId && !options.isBackfill) {
      try {
        const title = `[CORRELATED CAMPAIGN] ${metrics.riskLevel} Risk from ${displayName}`;
        const description = `Attack campaign detected by Aapki Nazar Contextual Correlation Engine.
Correlation Key: ${correlationKey}
Identity: ${displayName} (${identityType})
Contextual Risk Score: ${metrics.riskScore}/100 (${metrics.riskLevel})
Event Count: ${fullEventsList.length} (${blockedCount} blocked)
Categories: ${allCategories.join(", ")}
Targeted Endpoints: ${allEndpoints.join(", ")}
Explanation: ${metrics.explanation.summary}`;

        const createdInc = await incidentService.createIncident({
          title,
          description,
          severity: metrics.riskLevel,
          status: "OPEN",
          assignedTo: "Correlation-Engine",
          threatType: allCategories[0] || "Coordinated Attack Campaign",
          mitreTechnique: "T1190",
          confidence: "HIGH (Multi-Vector Correlated)",
          eventSource: "OFFICIAL_CRS",
          extractedPayload: allEndpoints.join(", "),
          payload: {
            campaignId: campaign.id,
            correlationKey,
            riskScore: metrics.riskScore,
            eventCount: fullEventsList.length
          }
        });

        if (createdInc) {
          linkedIncidentId = createdInc.incidentId;
        }
      } catch (incErr) {
        console.error("[CORRELATION] Incident creation warning:", incErr.message);
      }
    }

    // Update campaign record in DB (monotonically)
    const updatedCampaign = await localDb.updateCampaign(campaign.id, {
      firstSeen: monotonicFirstSeen,
      lastSeen: monotonicLastSeen,
      eventCount: fullEventsList.length,
      blockedCount,
      riskScore: metrics.riskScore,
      riskLevel: metrics.riskLevel,
      incidentId: linkedIncidentId,
      targetEndpoints: allEndpoints,
      attackCategories: allCategories
    });

    // Save structured risk explanation
    await localDb.saveCampaignRiskExplanation({
      campaignId: campaign.id,
      severityScore: metrics.severityScore,
      frequencyScore: metrics.frequencyScore,
      diversityScore: metrics.diversityScore,
      persistenceScore: metrics.persistenceScore,
      targetScore: metrics.targetScore,
      explanationJson: metrics.explanation
    });

    // Real-time Socket.IO broadcasts
    if (this.io && !options.isBackfill) {
      if (isNewCampaign) {
        this.io.emit("campaign_created", updatedCampaign);
      } else {
        this.io.emit("campaign_updated", updatedCampaign);
      }

      if (isEscalation) {
        this.io.emit("campaign_escalated", {
          campaign: updatedCampaign,
          previousLevel: previousRiskLevel,
          newLevel: metrics.riskLevel,
          explanation: metrics.explanation
        });
        this.io.emit("dashboard_update_needed");
      }
    }

    return updatedCampaign;
  }

  /**
   * Idempotent historical backfill: Uses transactional reconciliation
   * Re-evaluates all stored WAF events chronologically into campaigns.
   */
  async backfillFromWafEvents(force = false) {
    const reconciliation = localDb.reconcileDatabaseCampaigns(force);
    const stats = await localDb.getCampaignStats();
    console.log(`[CORRELATION] Reconciliation backfill complete: ${reconciliation.eligibleCount} eligible events across ${reconciliation.campaignsCount} campaigns.`);
    return {
      success: true,
      processedEvents: reconciliation.eligibleCount,
      reconciliation,
      stats
    };
  }
}

const attackCorrelationService = new AttackCorrelationService();
module.exports = attackCorrelationService;
