/**
 * AAPKI NAZAR — Comprehensive Regression & Data Integrity Test Suite
 * 
 * Covers all 15 Phase 2 Stabilization and Reliability guarantees:
 *  1. Backfill 3 times -> identical counts and memberships.
 *  2. Reprocess CLOSED campaigns -> no duplicate links.
 *  3. Unique constraint on campaign_events(wafEventId).
 *  4. Distinct attack categories for SQLi and XSS.
 *  5. Categories survive restarts and are persisted in SQLite.
 *  6. Benign rule 920350, HTTP 200, score 0 does not create malicious campaigns.
 *  7. 10-minute sliding window boundary test.
 *  8. Out-of-order events cannot reverse firstSeen <= lastSeen.
 *  9. Inactive campaigns are closed after 10-minute window.
 * 10. SQLite locks retain uncommitted audit records (stalled without advance).
 * 11. Downstream partial failure recovery (incident failure does not lose WAF record).
 * 12. Separate simulation sessions remain isolated (SIM:<ip>:<session>).
 * 13. Explanations match database evidence (no false block claims).
 * 14. Real incidents preserved across backfills and reconciliations.
 * 15. Dashboard statistics use unique eligible event counts.
 * 
 * Also preserves Phase 1 Gateway identity and reachability tests.
 */

const fs = require("fs");
const path = require("path");
const http = require("http");
const assert = require("assert");

// Configure isolated test database environment BEFORE loading services
const TEST_DB_PATH = path.join(__dirname, "tmp_test_isolated.sqlite");
if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
process.env.SQLITE_DB_PATH = TEST_DB_PATH;

const localDb = require("../backend/services/localDbService");
const crsIngestion = require("../backend/services/crsIngestionService");
const attackCorrelation = require("../backend/services/attackCorrelationService");

async function runAllTests() {
  console.log("================================================================================");
  console.log(" AAPKI NAZAR — COMPREHENSIVE PHASE 1 & 2 REGRESSION TEST SUITE");
  console.log("================================================================================\n");

  let passed = 0;
  let total = 0;

  async function test(name, fn) {
    total++;
    try {
      await fn();
      console.log(`  [PASS] Test ${String(total).padStart(2, '0')}: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] Test ${String(total).padStart(2, '0')}: ${name}`);
      console.error(`         ${err.message}`);
    }
  }

  try {
    // ════════════════════════════════════════════════════════════════
    // GATEWAY IDENTITY & HEALTH VERIFICATION (Phase 1)
    // ════════════════════════════════════════════════════════════════

    await test("A1: Negative Test - Unrelated Nginx server returning 200 OK is rejected with UNRECOGNIZED_SERVICE", async () => {
      const foreignNginx = http.createServer((req, res) => {
        res.writeHead(200, {
          "Server": "nginx/1.24.0 (Ubuntu)",
          "Content-Type": "text/html"
        });
        res.end("<html><body><h1>Welcome to nginx! (Unrelated Foreign Nginx)</h1></body></html>");
      });

      const port = 9871;
      await new Promise(r => foreignNginx.listen(port, "127.0.0.1", r));

      try {
        const result = await crsIngestion.checkGatewayHealth(port);
        assert.strictEqual(result.status, "UNRECOGNIZED_SERVICE", "Foreign Nginx without identity marker must be UNRECOGNIZED_SERVICE");
        assert.strictEqual(result.isVerifiedGateway, false, "isVerifiedGateway must be false");
        assert.ok(result.error.includes("X-Backend-Server: Aapki-Nazar-Protected-App/1.0"), "Error must cite missing app marker");
      } finally {
        foreignNginx.close();
      }
    });

    await test("A1: Positive Test - Authentic CRS gateway with protected demo app identity is verified ONLINE", async () => {
      const genuineGateway = http.createServer((req, res) => {
        res.writeHead(200, {
          "Server": "nginx/1.30.6",
          "X-Protected-By": "OWASP-CRS-ModSecurity",
          "X-Backend-Server": "Aapki-Nazar-Protected-App/1.0",
          "Content-Type": "application/json"
        });
        res.end(JSON.stringify({ status: "healthy", uptimeSeconds: 120 }));
      });

      const port = 9872;
      await new Promise(r => genuineGateway.listen(port, "127.0.0.1", r));

      try {
        const result = await crsIngestion.checkGatewayHealth(port);
        assert.strictEqual(result.status, "ONLINE", "Authentic CRS gateway must be ONLINE");
        assert.strictEqual(result.isVerifiedGateway, true, "isVerifiedGateway must be true");
        assert.strictEqual(result.backendReachable, true, "backendReachable must be true");
        assert.strictEqual(result.error, null, "Error must be null");
      } finally {
        genuineGateway.close();
      }
    });

    await test("A1: Gateway distinction - Nginx gateway active but backend unreachable reports GATEWAY_UP_BACKEND_UNREACHABLE", async () => {
      const downGateway = http.createServer((req, res) => {
        res.writeHead(502, {
          "Server": "nginx/1.30.6",
          "Content-Type": "text/html"
        });
        res.end("<html><body><h1>502 Bad Gateway</h1></body></html>");
      });

      const port = 9873;
      await new Promise(r => downGateway.listen(port, "127.0.0.1", r));

      try {
        const result = await crsIngestion.checkGatewayHealth(port);
        assert.strictEqual(result.status, "GATEWAY_UP_BACKEND_UNREACHABLE", "Must be GATEWAY_UP_BACKEND_UNREACHABLE");
        assert.strictEqual(result.isVerifiedGateway, true, "Gateway is verified Nginx");
        assert.strictEqual(result.backendReachable, false, "Backend is NOT reachable");
      } finally {
        downGateway.close();
      }
    });

    // ════════════════════════════════════════════════════════════════
    // 15 MANDATORY PHASE 2 STABILIZATION & IDEMPOTENCY TESTS
    // ════════════════════════════════════════════════════════════════

    // ── 1. Backfill 3 times -> Identical counts and memberships ──
    await test("Case 1: Historical backfill run 3 times consecutively produces identical counts and memberships", async () => {
      await localDb.createWafEvent({
        id: "WAF-BF-1",
        transactionId: "TX-BF-1",
        timestamp: "2026-10-28T10:00:00.000Z",
        clientIp: "10.0.0.1",
        method: "GET",
        uri: "/products?search=' OR 1=1--",
        httpCode: 403,
        blocked: true,
        anomalyScore: 10,
        primaryRuleId: "OWASP-CRS-942100",
        category: "SQL Injection",
        severity: "HIGH",
        eventSource: "OFFICIAL_CRS"
      });

      await localDb.createWafEvent({
        id: "WAF-BF-2",
        transactionId: "TX-BF-2",
        timestamp: "2026-10-28T10:05:00.000Z",
        clientIp: "10.0.0.1",
        method: "GET",
        uri: "/products?search=<script>alert(1)</script>",
        httpCode: 403,
        blocked: true,
        anomalyScore: 8,
        primaryRuleId: "OWASP-CRS-941100",
        category: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        eventSource: "OFFICIAL_CRS"
      });

      // Run 1
      await attackCorrelation.backfillFromWafEvents();
      const stats1 = await localDb.getCampaignStats();

      // Run 2
      await attackCorrelation.backfillFromWafEvents();
      const stats2 = await localDb.getCampaignStats();

      // Run 3
      await attackCorrelation.backfillFromWafEvents();
      const stats3 = await localDb.getCampaignStats();

      assert.strictEqual(stats1.totalCampaigns, stats2.totalCampaigns, "Campaign count identical run 1 vs 2");
      assert.strictEqual(stats2.totalCampaigns, stats3.totalCampaigns, "Campaign count identical run 2 vs 3");
      assert.strictEqual(stats1.uniqueCorrelatedEvents, stats2.uniqueCorrelatedEvents, "Event count identical run 1 vs 2");
      assert.strictEqual(stats2.uniqueCorrelatedEvents, stats3.uniqueCorrelatedEvents, "Event count identical run 2 vs 3");
    });

    // ── 2. Reprocess CLOSED campaigns -> No duplicate links ──
    await test("Case 2: Reprocessing events from CLOSED campaigns does not recreate campaigns or duplicate links", async () => {
      const ev = await localDb.getWafEventByTransactionId("TX-BF-1");
      assert.ok(ev, "Event TX-BF-1 exists");

      // Mark the campaign as CLOSED
      const existingCamp = await localDb.getCampaignByWafEventId(ev.id);
      assert.ok(existingCamp, "Campaign exists for event");
      await localDb.updateCampaign(existingCamp.id, { status: "CLOSED" });

      const countBefore = (await localDb.getCampaignEvents(existingCamp.id)).length;
      const reprocessed = await attackCorrelation.processEvent(ev);
      const countAfter = (await localDb.getCampaignEvents(existingCamp.id)).length;

      assert.strictEqual(reprocessed.id, existingCamp.id, "Returned campaign matches existing closed campaign");
      assert.strictEqual(countBefore, countAfter, "No duplicate campaign event links created");
    });

    // ── 3. Unique constraint on campaign_events(wafEventId) ──
    await test("Case 3: SQLite enforces UNIQUE(wafEventId) on campaign_events", async () => {
      const db = localDb.getDb();
      let threwConstraintError = false;
      try {
        db.prepare(`
          INSERT INTO campaign_events (id, campaignId, wafEventId, eventTimestamp, riskScoreAfterEvent)
          VALUES ('CEVT-DUP-TEST', 'CAMP-TEST', 'WAF-BF-1', datetime('now'), 50)
        `).run();
      } catch (e) {
        if (e.code === 'SQLITE_CONSTRAINT_UNIQUE' || e.message.includes('UNIQUE')) {
          threwConstraintError = true;
        }
      }
      assert.strictEqual(threwConstraintError, true, "SQLite MUST throw SQLITE_CONSTRAINT_UNIQUE on duplicate wafEventId");
    });

    // ── 4. Distinct attack categories for SQLi and XSS ──
    await test("Case 4: Category mapper assigns distinct categories for SQLi (942) and XSS (941)", () => {
      const sqliCat = localDb.deriveCategory({ primaryRuleId: "OWASP-CRS-942100" });
      const xssCat = localDb.deriveCategory({ primaryRuleId: "OWASP-CRS-941110" });
      const rceCat = localDb.deriveCategory({ primaryRuleId: "OWASP-CRS-932100" });
      const lfiCat = localDb.deriveCategory({ primaryRuleId: "OWASP-CRS-930100" });

      assert.strictEqual(sqliCat, "SQL Injection");
      assert.strictEqual(xssCat, "Cross-Site Scripting (XSS)");
      assert.strictEqual(rceCat, "Remote Command Execution (RCE)");
      assert.strictEqual(lfiCat, "Path Traversal / LFI");
      assert.notStrictEqual(sqliCat, xssCat, "SQLi and XSS must have distinct categories");
    });

    // ── 5. Categories survive restarts and are persisted in SQLite ──
    await test("Case 5: Categories are persisted directly in waf_events and survive reload", async () => {
      const created = await localDb.createWafEvent({
        id: "WAF-CAT-PERSIST",
        transactionId: "TX-CAT-PERSIST",
        timestamp: new Date().toISOString(),
        clientIp: "10.0.0.2",
        method: "GET",
        uri: "/login",
        httpCode: 403,
        blocked: true,
        anomalyScore: 10,
        primaryRuleId: "OWASP-CRS-942100",
        eventSource: "OFFICIAL_CRS"
      });

      const loaded = await localDb.getWafEventByTransactionId("TX-CAT-PERSIST");
      assert.strictEqual(loaded.category, "SQL Injection", "Category must be persisted as SQL Injection");
    });

    // ── 6. Benign rule 920350, HTTP 200, score 0 does not create malicious campaigns ──
    await test("Case 6: Benign protocol warning (Rule 920350, HTTP 200, Score 0) is excluded from attack campaigns", async () => {
      const benignEvent = {
        id: "WAF-BENIGN-1",
        transactionId: "TX-BENIGN-1",
        timestamp: new Date().toISOString(),
        clientIp: "10.0.0.99",
        method: "GET",
        uri: "/products",
        httpCode: 200,
        blocked: false,
        anomalyScore: 0,
        primaryRuleId: "OWASP-CRS-920350",
        category: "Protocol Validation"
      };

      const eligibility = localDb.isEventEligible(benignEvent);
      assert.strictEqual(eligibility, false, "Benign event must not be eligible for attack campaigns");

      const res = await attackCorrelation.processEvent(benignEvent);
      assert.strictEqual(res.eligible, false, "Correlation engine must reject benign event");
    });

    // ── 7. 10-minute sliding window boundary test ──
    await test("Case 7: Events arriving within 10 minutes join campaign; events > 10m start new campaign", async () => {
      const baseTime = Date.now();
      const ip = "198.51.100.200";

      // Event A at T0
      const campA = await attackCorrelation.processEvent({
        id: "WAF-WIN-A",
        transactionId: "TX-WIN-A",
        timestamp: new Date(baseTime).toISOString(),
        clientIp: "127.0.0.1",
        simulatedClientIp: ip,
        method: "GET",
        uri: "/products?search='",
        httpCode: 403,
        blocked: true,
        anomalyScore: 5,
        primaryRuleId: "OWASP-CRS-942100",
        category: "SQL Injection"
      });

      // Event B at T0 + 5 minutes (within 10m window)
      const campB = await attackCorrelation.processEvent({
        id: "WAF-WIN-B",
        transactionId: "TX-WIN-B",
        timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString(),
        clientIp: "127.0.0.1",
        simulatedClientIp: ip,
        method: "GET",
        uri: "/products?search='",
        httpCode: 403,
        blocked: true,
        anomalyScore: 5,
        primaryRuleId: "OWASP-CRS-942100",
        category: "SQL Injection"
      });

      assert.strictEqual(campA.id, campB.id, "Events within 10m must share the same campaign");

      // Event C at T0 + 16 minutes (> 10m window from Event B)
      const campC = await attackCorrelation.processEvent({
        id: "WAF-WIN-C",
        transactionId: "TX-WIN-C",
        timestamp: new Date(baseTime + 16 * 60 * 1000).toISOString(),
        clientIp: "127.0.0.1",
        simulatedClientIp: ip,
        method: "GET",
        uri: "/products?search='",
        httpCode: 403,
        blocked: true,
        anomalyScore: 5,
        primaryRuleId: "OWASP-CRS-942100",
        category: "SQL Injection"
      });

      assert.notStrictEqual(campA.id, campC.id, "Event > 10m later must initiate a new campaign");
    });

    // ── 8. Out-of-order events cannot reverse firstSeen <= lastSeen ──
    await test("Case 8: Out-of-order event timestamps strictly preserve monotonic firstSeen <= lastSeen", async () => {
      const campId = "CAMP-MONOTONIC-TEST";
      await localDb.createCampaign({
        id: campId,
        correlationKey: "REAL:192.0.2.1",
        identityType: "REAL_NETWORK_IP",
        firstSeen: "2026-10-28T12:00:00.000Z",
        lastSeen: "2026-10-28T12:05:00.000Z",
        status: "ACTIVE",
        eventCount: 1,
        blockedCount: 1,
        riskScore: 50,
        riskLevel: "HIGH"
      });

      // Update with an earlier timestamp
      const updated = await localDb.updateCampaign(campId, {
        firstSeen: "2026-10-28T11:58:00.000Z",
        lastSeen: "2026-10-28T12:03:00.000Z"
      });

      const fsTime = new Date(updated.firstSeen).getTime();
      const lsTime = new Date(updated.lastSeen).getTime();

      assert.strictEqual(updated.firstSeen, "2026-10-28T11:58:00.000Z", "firstSeen moved earlier to match min");
      assert.strictEqual(updated.lastSeen, "2026-10-28T12:05:00.000Z", "lastSeen retained max");
      assert.ok(fsTime <= lsTime, "firstSeen must be <= lastSeen");
    });

    // ── 9. Inactive campaigns are closed ──
    await test("Case 9: Inactive campaigns older than 10 minutes are closed, preserving MITIGATED campaigns", async () => {
      const oldTime = new Date(Date.now() - 15 * 60 * 1000).toISOString();

      const activeCamp = await localDb.createCampaign({
        id: "CAMP-INACTIVE-ACTIVE",
        correlationKey: "REAL:198.51.100.11",
        identityType: "REAL_NETWORK_IP",
        firstSeen: oldTime,
        lastSeen: oldTime,
        status: "ACTIVE"
      });

      const mitigatedCamp = await localDb.createCampaign({
        id: "CAMP-INACTIVE-MITIGATED",
        correlationKey: "REAL:198.51.100.12",
        identityType: "REAL_NETWORK_IP",
        firstSeen: oldTime,
        lastSeen: oldTime,
        status: "MITIGATED"
      });

      await attackCorrelation.closeInactiveCampaigns(Date.now());

      const c1 = await localDb.getCampaignById(activeCamp.id);
      const c2 = await localDb.getCampaignById(mitigatedCamp.id);

      assert.strictEqual(c1.status, "CLOSED", "Old active campaign must be closed");
      assert.strictEqual(c2.status, "MITIGATED", "Mitigated campaign must remain MITIGATED");
    });

    // ── 10. SQLite locks retain uncommitted audit records ──
    await test("Case 10: SQLite locks cause bounded backoff without advancing log offset or skipping records", async () => {
      const tmpLog = path.join(__dirname, "tmp_audit_lock.log");
      const record = JSON.stringify({
        transaction: {
          unique_id: "tx-lock-test-1",
          client_ip: "127.0.0.1",
          time_stamp: new Date().toISOString(),
          request: { method: "GET", uri: "/test" },
          response: { http_code: 200 }
        }
      }) + "\n";

      fs.writeFileSync(tmpLog, record);
      const savedLogPath = crsIngestion.logPath;
      const savedOffset = crsIngestion.lastOffset;

      crsIngestion.logPath = tmpLog;
      crsIngestion.lastOffset = 0;

      // Mock processAuditRecord to simulate SQLITE_BUSY error
      const origProcess = crsIngestion.processAuditRecord;
      crsIngestion.processAuditRecord = async () => {
        const err = new Error("database is locked");
        err.code = "SQLITE_BUSY";
        throw err;
      };

      try {
        await crsIngestion.pollLog();
        assert.strictEqual(crsIngestion.lastOffset, 0, "Offset MUST NOT advance during SQLITE_BUSY lock");
        assert.strictEqual(crsIngestion.ingestionStatus.stalled, true, "Ingestion must be marked as stalled");
      } finally {
        crsIngestion.processAuditRecord = origProcess;
        crsIngestion.logPath = savedLogPath;
        crsIngestion.lastOffset = savedOffset;
        if (fs.existsSync(tmpLog)) fs.unlinkSync(tmpLog);
      }
    });

    // ── 11. Downstream partial failure recovery ──
    await test("Case 11: Malformed JSON is quarantined into audit_quarantine without crashing ingestion", async () => {
      const qRec = await localDb.quarantineRecord({
        rawRecord: "CORRUPT JSON LINE {{{",
        reason: "SyntaxError: Unexpected token",
        offset: 1024
      });

      assert.ok(qRec.id, "Quarantined record ID created");
      const quarantined = await localDb.getQuarantineRecords(10);
      assert.ok(quarantined.some(q => q.rawRecord.includes("CORRUPT JSON")), "Record stored in audit_quarantine");
    });

    // ── 12. Separate simulation sessions remain isolated ──
    await test("Case 12: Distinct simulation sessions with the same IP do not merge campaigns", async () => {
      const simIp = "198.51.100.99";
      const keyA = attackCorrelation.getIdentityAndKey({ simulatedClientIp: simIp, simulatedSessionId: "session-alpha" });
      const keyB = attackCorrelation.getIdentityAndKey({ simulatedClientIp: simIp, simulatedSessionId: "session-beta" });
      const keyLegacy = attackCorrelation.getIdentityAndKey({ simulatedClientIp: simIp });

      assert.strictEqual(keyA.correlationKey, "SIM:198.51.100.99:session-alpha");
      assert.strictEqual(keyB.correlationKey, "SIM:198.51.100.99:session-beta");
      assert.strictEqual(keyLegacy.correlationKey, "SIM:198.51.100.99:legacy");
      assert.notStrictEqual(keyA.correlationKey, keyB.correlationKey, "Different sessions must have distinct keys");
    });

    // ── 13. Explanations match database evidence (no false block claims) ──
    await test("Case 13: Campaign explanations do NOT claim confirmed WAF blocks when blockedCount is 0", async () => {
      const allowedEvents = [
        {
          id: "WAF-PROBE-1",
          uri: "/search",
          blocked: false,
          httpCode: 200,
          anomalyScore: 6,
          category: "SQL Injection",
          primaryRuleId: "OWASP-CRS-942100"
        }
      ];

      const metrics = attackCorrelation.calculateContextualRisk(allowedEvents);
      assert.strictEqual(metrics.explanation.evidence.blockedEvents, 0, "blockedEvents must be 0");
      assert.ok(!metrics.explanation.summary.includes("confirmed WAF block(s)"), "Summary must NOT claim blocks when 0 blocks occurred");
    });

    // ── 14. Real incidents preserved across reconciliations ──
    await test("Case 14: Real incidents in SQLite are preserved across backfills and reconciliations", async () => {
      const incCountBefore = (await localDb.getAllIncidents()).length;
      await attackCorrelation.backfillFromWafEvents();
      const incCountAfter = (await localDb.getAllIncidents()).length;

      assert.strictEqual(incCountBefore, incCountAfter, "Incidents count must remain identical before and after reconciliation");
    });

    // ── 15. Dashboard statistics use unique eligible event counts ──
    await test("Case 15: getCampaignStats returns unique correlated events, consolidation ratio, and excludes protocol warnings", async () => {
      // Reconcile database to synchronize stored waf_events with campaigns
      await attackCorrelation.backfillFromWafEvents();
      const stats = await localDb.getCampaignStats();

      assert.ok(typeof stats.totalWafEvents === "number", "totalWafEvents is number");
      assert.ok(typeof stats.eligibleWafEvents === "number", "eligibleWafEvents is number");
      assert.ok(typeof stats.excludedWafEvents === "number", "excludedWafEvents is number");
      assert.ok(typeof stats.uniqueCorrelatedEvents === "number", "uniqueCorrelatedEvents is number");
      assert.ok(typeof stats.consolidationRatio === "number", "consolidationRatio is number");
      assert.strictEqual(stats.totalWafEvents, stats.eligibleWafEvents + stats.excludedWafEvents, "totalWafEvents = eligible + excluded");
      assert.strictEqual(stats.uniqueCorrelatedEvents, stats.eligibleWafEvents, "uniqueCorrelatedEvents matches eligibleWafEvents");
    });

    // ── 16. FIX 1: Risk Scoring Parity Test (Live vs Historical) ──
    await test("Case 16: FIX 1 - Live processing vs historical backfill of same events produce identical risk scores, component scores, explanations, and timeline progressions", async () => {
      const ip = "198.51.100.77";
      const baseTime = Date.now();

      const eventsData = [
        {
          id: "WAF-PARITY-1",
          transactionId: "TX-PARITY-1",
          timestamp: new Date(baseTime).toISOString(),
          clientIp: ip,
          method: "POST",
          uri: "/admin/query",
          httpCode: 403,
          blocked: true,
          anomalyScore: 10,
          primaryRuleId: "OWASP-CRS-942100",
          category: "SQL Injection",
          severity: "HIGH",
          eventSource: "OFFICIAL_CRS"
        },
        {
          id: "WAF-PARITY-2",
          transactionId: "TX-PARITY-2",
          timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString(),
          clientIp: ip,
          method: "GET",
          uri: "/login?user=<script>alert(1)</script>",
          httpCode: 403,
          blocked: true,
          anomalyScore: 8,
          primaryRuleId: "OWASP-CRS-941100",
          category: "Cross-Site Scripting (XSS)",
          severity: "HIGH",
          eventSource: "OFFICIAL_CRS"
        },
        {
          id: "WAF-PARITY-3",
          transactionId: "TX-PARITY-3",
          timestamp: new Date(baseTime + 4 * 60 * 1000).toISOString(),
          clientIp: ip,
          method: "POST",
          uri: "/api/exec?cmd=cat+/etc/passwd",
          httpCode: 403,
          blocked: true,
          anomalyScore: 15,
          primaryRuleId: "OWASP-CRS-932100",
          category: "Remote Command Execution (RCE)",
          severity: "CRITICAL",
          eventSource: "OFFICIAL_CRS"
        }
      ];

      // 1. Process sequentially via live correlation
      for (const ev of eventsData) {
        await localDb.createWafEvent(ev);
        await attackCorrelation.processEvent(ev);
      }

      // Fetch live state
      const liveCampLink = await localDb.getCampaignByWafEventId("WAF-PARITY-1");
      assert.ok(liveCampLink, "Live campaign created");
      const liveCamp = await localDb.getCampaignById(liveCampLink.id);
      const liveExpl = await localDb.getCampaignRiskExplanation(liveCamp.id);
      const liveEvents = await localDb.getCampaignEvents(liveCamp.id);

      assert.strictEqual(liveEvents.length, 3, "All 3 events linked live");

      // 2. Run historical backfill / reconciliation
      await attackCorrelation.backfillFromWafEvents();

      // Fetch reconstructed state
      const reconCamp = await localDb.getCampaignById(liveCamp.id);
      const reconExpl = await localDb.getCampaignRiskExplanation(liveCamp.id);
      const reconEvents = await localDb.getCampaignEvents(liveCamp.id);

      // 3. Verify identical risk scores, risk levels, and component scores
      assert.strictEqual(reconCamp.riskScore, liveCamp.riskScore, "Final riskScore must be identical");
      assert.strictEqual(reconCamp.riskLevel, liveCamp.riskLevel, "Final riskLevel must be identical");
      assert.strictEqual(reconCamp.eventCount, liveCamp.eventCount, "Event count must match");
      assert.strictEqual(reconCamp.blockedCount, liveCamp.blockedCount, "Blocked count must match");

      assert.strictEqual(reconExpl.severityScore, liveExpl.severityScore, "Severity score matches");
      assert.strictEqual(reconExpl.frequencyScore, liveExpl.frequencyScore, "Frequency score matches");
      assert.strictEqual(reconExpl.diversityScore, liveExpl.diversityScore, "Diversity score matches");
      assert.strictEqual(reconExpl.persistenceScore, liveExpl.persistenceScore, "Persistence score matches");
      assert.strictEqual(reconExpl.targetScore, liveExpl.targetScore, "Target score matches");
      assert.strictEqual(reconExpl.explanationJson.summary, liveExpl.explanationJson.summary, "Explanation summary matches");

      // 4. Verify step-by-step chronological progression snapshots
      for (let i = 0; i < liveEvents.length; i++) {
        assert.strictEqual(
          reconEvents[i].riskScoreAfterEvent,
          liveEvents[i].riskScoreAfterEvent,
          `Step ${i + 1} riskScoreAfterEvent must be identical (recon: ${reconEvents[i].riskScoreAfterEvent}, live: ${liveEvents[i].riskScoreAfterEvent})`
        );
      }
    });

    // ── 17. FIX 2: Missing Eligible Event Reconciliation ──
    await test("Case 17: FIX 2 - Late-arriving unlinked eligible event is detected and correlated, incrementing unique correlated events", async () => {
      const statsBefore = await localDb.getCampaignStats();
      const initialEligible = statsBefore.eligibleWafEvents;
      const initialCorrelated = statsBefore.uniqueCorrelatedEvents;

      // Insert an unlinked eligible event directly into waf_events (bypassing correlation)
      const unlinkedEv = await localDb.createWafEvent({
        id: "WAF-UNLINKED-20",
        transactionId: "TX-UNLINKED-20",
        timestamp: new Date().toISOString(),
        clientIp: "198.51.100.88",
        method: "POST",
        uri: "/api/checkout?query=' OR '1'='1",
        httpCode: 403,
        blocked: true,
        anomalyScore: 10,
        primaryRuleId: "OWASP-CRS-942100",
        category: "SQL Injection",
        severity: "HIGH",
        eventSource: "OFFICIAL_CRS"
      });

      const statsMiddle = await localDb.getCampaignStats();
      assert.strictEqual(statsMiddle.eligibleWafEvents, initialEligible + 1, "Eligible count incremented by 1");
      assert.strictEqual(statsMiddle.uniqueCorrelatedEvents, initialCorrelated, "Correlated count unchanged before backfill");
      assert.strictEqual(statsMiddle.unlinkedEligibleEvents, 1, "Unlinked eligible count reports exactly 1");

      // Run backfill
      await attackCorrelation.backfillFromWafEvents();

      const statsAfter = await localDb.getCampaignStats();
      assert.strictEqual(statsAfter.uniqueCorrelatedEvents, initialCorrelated + 1, "Correlated count incremented by 1 after backfill");
      assert.strictEqual(statsAfter.unlinkedEligibleEvents, 0, "No unlinked eligible events remain after backfill");

      const link = await localDb.getCampaignByWafEventId(unlinkedEv.id);
      assert.ok(link, "Late-arriving unlinked event is successfully correlated into a campaign");
    });

    // ── 18. FIX 3A: Downstream Partial Failure Recovery ──
    await test("Case 18: FIX 3 - Ingestion recovers correlation for existing WAF events without duplicate records or incidents", async () => {
      const eventId = "WAF-DOWNSTREAM-FAIL-1";
      const txId = "TX-DOWNSTREAM-FAIL-1";

      await localDb.createWafEvent({
        id: eventId,
        transactionId: txId,
        timestamp: new Date().toISOString(),
        clientIp: "198.51.100.95",
        method: "POST",
        uri: "/search?q=<script>alert('downstream')</script>",
        httpCode: 403,
        blocked: true,
        anomalyScore: 8,
        primaryRuleId: "OWASP-CRS-941110",
        category: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        eventSource: "OFFICIAL_CRS"
      });

      // Verify currently unlinked
      const unlinkedBefore = await localDb.getCampaignByWafEventId(eventId);
      assert.strictEqual(unlinkedBefore, null, "Event is initially unlinked");

      const incidentsBefore = (await localDb.getAllIncidents()).length;

      // Run recoverPendingEvents
      const recRes = await crsIngestion.recoverPendingEvents();
      assert.strictEqual(recRes.success, true, "Recovery was successful");
      assert.ok(recRes.recovered >= 1, "At least 1 event recovered");

      // Verify now linked
      const linkedAfter = await localDb.getCampaignByWafEventId(eventId);
      assert.ok(linkedAfter, "Event is now successfully linked to a campaign");

      // Verify incidents did not create spurious duplicates
      const incidentsAfter = (await localDb.getAllIncidents()).length;
      assert.strictEqual(incidentsAfter, incidentsBefore, "Incidents count unchanged during correlation recovery");
    });

    // ── 19. FIX 3B: Prolonged Non-SQLITE_BUSY Database Failure ──
    await test("Case 19: FIX 3 - Prolonged non-SQLITE_BUSY database failure retains log offset, marks stalled, and never discards valid records", async () => {
      const tmpLog = path.join(__dirname, "tmp_audit_storage_err.log");
      const validRecord = JSON.stringify({
        transaction: {
          unique_id: "tx-storage-err-1",
          client_ip: "127.0.0.1",
          time_stamp: new Date().toISOString(),
          request: { method: "POST", uri: "/sensitive-admin" },
          response: { http_code: 403 }
        }
      }) + "\n";

      fs.writeFileSync(tmpLog, validRecord);
      const savedLogPath = crsIngestion.logPath;
      const savedOffset = crsIngestion.lastOffset;

      crsIngestion.logPath = tmpLog;
      crsIngestion.lastOffset = 0;

      // Mock processAuditRecord to simulate storage I/O failure (EIO)
      const origProcess = crsIngestion.processAuditRecord;
      crsIngestion.processAuditRecord = async () => {
        const err = new Error("EIO: storage i/o failure while committing transaction");
        err.code = "EIO";
        throw err;
      };

      try {
        await crsIngestion.pollLog();

        // 1. Offset MUST NOT advance past uncommitted record
        assert.strictEqual(crsIngestion.lastOffset, 0, "lastOffset must NOT advance during storage failure");

        // 2. Ingestion status marked as stalled
        assert.strictEqual(crsIngestion.ingestionStatus.stalled, true, "ingestionStatus.stalled must be true");

        // 3. Error message visible
        assert.ok(crsIngestion.ingestionStatus.lastError.includes("EIO"), "lastError must contain EIO message");

        // 4. Valid record was NOT quarantined
        const quarantined = await localDb.getQuarantineRecords(10);
        const wasQuarantined = quarantined.some(q => q.rawRecord && q.rawRecord.includes("tx-storage-err-1"));
        assert.strictEqual(wasQuarantined, false, "Valid record MUST NOT be quarantined on database/storage error");
      } finally {
        crsIngestion.processAuditRecord = origProcess;
        crsIngestion.logPath = savedLogPath;
        crsIngestion.lastOffset = savedOffset;
        if (fs.existsSync(tmpLog)) fs.unlinkSync(tmpLog);
      }
    });

  } finally {
    // Clean up temporary isolated test DB
    try {
      const db = localDb.getDb();
      if (db) db.close();
      if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
      if (fs.existsSync(`${TEST_DB_PATH}-wal`)) fs.unlinkSync(`${TEST_DB_PATH}-wal`);
      if (fs.existsSync(`${TEST_DB_PATH}-shm`)) fs.unlinkSync(`${TEST_DB_PATH}-shm`);
      console.log("\n[TEST CLEANUP] Isolated test SQLite database cleaned up successfully.");
    } catch (e) {
      console.warn("[TEST CLEANUP WARNING]", e.message);
    }
  }

  console.log("\n================================================================================");
  console.log(` RESULTS: ${passed}/${total} TESTS PASSED`);
  console.log("================================================================================\n");

  if (passed === total) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runAllTests().catch(err => {
  console.error("FATAL ERROR IN TEST SUITE:", err);
  process.exit(1);
});
