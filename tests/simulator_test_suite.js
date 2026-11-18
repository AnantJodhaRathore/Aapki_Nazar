/**
 * AAPKI NAZAR — High-Performance Synthetic Traffic Simulator Test Suite
 * 
 * Verifies all 13 core requirements for simulator repair and stabilization:
 *  1. Accurate Start: Simulator starts cleanly and emits state changes.
 *  2. Accurate Stop: Simulator stops completely and clears all timers.
 *  3. Start Idempotency: Multiple starts do not duplicate timers or desynchronize state.
 *  4. Stop Idempotency: Multiple stops do not throw errors or desynchronize state.
 *  5. Traffic Volume (Rate Control): 1–10 EPS rate slider increases throughput correctly.
 *  6. Attack Intensity (0% Benign Baseline): 0% attack intensity produces 100% clean benign logs (0 false alarms).
 *  7. Attack Intensity (100% Malicious): 100% attack intensity produces 100% detected threats.
 *  8. Dynamic Live Configuration: updateConfig updates running loop without stopping or races.
 *  9. Synthetic Attribution: Emitted events are strictly tagged `isSimulated: true`, `sensor: "SYNTHETIC-SIMULATOR"`, RFC5737 IPs.
 * 10. Database Isolation: Synthetic traffic ticks NEVER insert into `waf_events` table.
 * 11. Incident Flooding Protection: No incidents created when `createIncidents: false` (default).
 * 12. Throttled Demonstration Incidents: When opted in, incidents are tagged `eventSource: "SIMULATED"` and rate-limited.
 * 13. Baseline Data Preservation: Original 175 WAF events and 29 incidents remain untouched.
 */

const assert = require("assert");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

// Use an isolated test database for safe testing
const TEST_DB_PATH = path.join(__dirname, "tmp_test_simulator.sqlite");
if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
process.env.SQLITE_DB_PATH = TEST_DB_PATH;

const localDb = require("../backend/services/localDbService");
const { SimulatorService } = require("../backend/services/simulatorService");
const incidentService = require("../backend/services/incidentService");

// Mock Socket.IO implementation
class MockSocketIO {
  constructor() {
    this.events = [];
  }
  emit(event, data) {
    this.events.push({ event, data, time: Date.now() });
  }
  clear() {
    this.events = [];
  }
  findLast(event) {
    const matched = this.events.filter(e => e.event === event);
    return matched.length > 0 ? matched[matched.length - 1].data : null;
  }
}

async function runSimulatorTestSuite() {
  console.log("================================================================================");
  console.log(" AAPKI NAZAR — SYNTHETIC TRAFFIC SIMULATOR TEST SUITE");
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
      console.error(`         ${err.stack || err.message}`);
    }
  }

  const mockIo = new MockSocketIO();
  let sim = new SimulatorService();
  sim.setIo(mockIo);

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Simulator Start
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Simulator starts cleanly and emits state changes", async () => {
    mockIo.clear();
    const res = sim.startSimulator(mockIo, { eps: 4, attackIntensity: 0.25, createIncidents: false });
    assert.strictEqual(res.isRunning, true, "Should return isRunning = true");
    assert.strictEqual(sim.isRunning, true, "Internal state should be running");
    assert.strictEqual(sim.config.eps, 4, "EPS should be set to 4");
    assert.strictEqual(sim.config.attackIntensity, 0.25, "Attack intensity should be 0.25");
    assert.strictEqual(sim.config.createIncidents, false, "Create incidents should be false");
    
    // Check Socket.IO broadcast
    const stateEvent = mockIo.findLast("simulator_state_changed");
    assert.ok(stateEvent, "Must broadcast simulator_state_changed event");
    assert.strictEqual(stateEvent.isRunning, true, "Broadcasted state must be running");
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. Start Idempotency
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Multiple start calls are idempotent (no duplicate timers)", async () => {
    const handleBefore = sim.timerHandle;
    const sessionBefore = sim.sessionId;
    const res = sim.startSimulator(mockIo, { eps: 4 });
    assert.strictEqual(res.isRunning, true);
    assert.strictEqual(sim.sessionId, sessionBefore, "Session ID should remain stable");
    assert.strictEqual(sim.timerHandle, handleBefore, "Timer handle must not be duplicated");
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. Simulator Stop
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Simulator stops completely and clears timer handle", async () => {
    mockIo.clear();
    const res = sim.stopSimulator();
    assert.strictEqual(res.isRunning, false, "Should return isRunning = false");
    assert.strictEqual(sim.isRunning, false, "Internal state should be stopped");
    assert.strictEqual(sim.timerHandle, null, "Timer handle must be null after stop");

    // Check Socket.IO broadcast
    const stateEvent = mockIo.findLast("simulator_state_changed");
    assert.ok(stateEvent, "Must broadcast simulator_state_changed on stop");
    assert.strictEqual(stateEvent.isRunning, false, "Broadcasted state must be stopped");
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Stop Idempotency
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Multiple stop calls are idempotent with no exceptions", async () => {
    const res = sim.stopSimulator();
    assert.strictEqual(res.isRunning, false);
    assert.strictEqual(sim.timerHandle, null);
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 5. Traffic Volume (Rate Slider Mapping)
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Traffic volume accepts 1–10 EPS and clamps bounds correctly", async () => {
    // 1 EPS (1000ms)
    sim.updateConfig({ eps: 1 });
    assert.strictEqual(sim.config.eps, 1);

    // 10 EPS (100ms)
    sim.updateConfig({ eps: 10 });
    assert.strictEqual(sim.config.eps, 10);

    // Clamp low (< 1 -> 1)
    sim.updateConfig({ eps: 0 });
    assert.strictEqual(sim.config.eps, 1);

    // Clamp high (> 10 -> 10)
    sim.updateConfig({ eps: 15 });
    assert.strictEqual(sim.config.eps, 10);

    // Legacy intervalMs mapping (500ms -> 2 EPS)
    sim.updateConfig({ interval: 500 });
    assert.strictEqual(sim.config.eps, 2);
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 6. Attack Intensity (0% Clean Baseline)
  // ─────────────────────────────────────────────────────────────────────────────
  await test("0% attack intensity generates 100% clean benign logs (0 false alarms)", async () => {
    sim.resetCounters();
    sim.config.attackIntensity = 0.0;
    mockIo.clear();

    for (let i = 0; i < 25; i++) {
      await sim.generateAndEmitLog();
    }

    assert.strictEqual(sim.stats.totalGenerated, 25, "Must generate 25 events");
    assert.strictEqual(sim.stats.benignCount, 25, "All 25 must be benign");
    assert.strictEqual(sim.stats.maliciousCount, 0, "0 malicious events");
    assert.strictEqual(sim.stats.detectedCount, 0, "0 threats detected (no false positives)");

    // Inspect emitted events
    const telemetryEvents = mockIo.events.filter(e => e.event === "telemetry_stream");
    assert.strictEqual(telemetryEvents.length, 25);
    for (const ev of telemetryEvents) {
      assert.strictEqual(ev.data.action, "ALLOWED", "Clean traffic must have action ALLOWED");
      assert.strictEqual(ev.data.statusCode, 200, "Clean traffic must return 200");
      assert.strictEqual(ev.data.threatScore, 0, "Clean traffic must have threat score 0");
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 7. Attack Intensity (100% Malicious)
  // ─────────────────────────────────────────────────────────────────────────────
  await test("100% attack intensity generates 100% detected threats", async () => {
    sim.resetCounters();
    sim.config.attackIntensity = 1.0;
    mockIo.clear();

    for (let i = 0; i < 25; i++) {
      await sim.generateAndEmitLog();
    }

    assert.strictEqual(sim.stats.totalGenerated, 25, "Must generate 25 events");
    assert.strictEqual(sim.stats.maliciousCount, 25, "All 25 must be malicious");
    assert.strictEqual(sim.stats.benignCount, 0, "0 benign events");
    assert.strictEqual(sim.stats.detectedCount, 25, "All 25 attacks must be detected by custom sensor");

    // Inspect emitted events
    const telemetryEvents = mockIo.events.filter(e => e.event === "telemetry_stream");
    assert.strictEqual(telemetryEvents.length, 25);
    for (const ev of telemetryEvents) {
      assert.strictEqual(ev.data.action, "DETECTED", "Malicious traffic must have action DETECTED");
      assert.ok(ev.data.threatScore >= 40, `Threat score must be >= 40 (got ${ev.data.threatScore})`);
      assert.ok(["SQL Injection", "XSS", "Cross-Site Scripting (XSS)", "Command Injection", "Path Traversal", "Server-Side Request Forgery", "SSRF", "Log4j / Remote Execution", "High Entropy Vector"].includes(ev.data.threatType), `Valid threat type expected (got ${ev.data.threatType})`);
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 8. Dynamic Live Configuration Update
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Dynamic live config update changes rate and intensity without stopping", async () => {
    sim.startSimulator(mockIo, { eps: 2, attackIntensity: 0.1 });
    assert.strictEqual(sim.isRunning, true);

    mockIo.clear();
    const updateRes = sim.updateConfig({ eps: 8, attackIntensity: 0.75 });
    assert.strictEqual(updateRes.success, true);
    assert.strictEqual(updateRes.isRunning, true, "Simulator must remain running after config update");
    assert.strictEqual(sim.config.eps, 8);
    assert.strictEqual(sim.config.attackIntensity, 0.75);

    // Check state broadcast
    const stateEvent = mockIo.findLast("simulator_state_changed");
    assert.ok(stateEvent);
    assert.strictEqual(stateEvent.config.eps, 8);
    assert.strictEqual(stateEvent.config.attackIntensity, 0.75);

    sim.stopSimulator();
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 9. Attribution and Synthetic Tagging
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Synthetic events are explicitly tagged SIMULATED with RFC5737 IPs", async () => {
    mockIo.clear();
    sim.config.attackIntensity = 0.5;
    await sim.generateAndEmitLog();

    const ev = mockIo.findLast("telemetry_stream");
    assert.ok(ev, "Event must be emitted");
    assert.strictEqual(ev.isSimulated, true, "Must have isSimulated = true");
    assert.strictEqual(ev.sensor, "SYNTHETIC-SIMULATOR", "Must be attributed to SYNTHETIC-SIMULATOR");
    
    // Check IP belongs to RFC 5737 documentation blocks
    const ip = ev.sourceIp;
    const isDocIp = ip.startsWith("192.0.2.") || ip.startsWith("198.51.100.") || ip.startsWith("203.0.113.");
    assert.ok(isDocIp, `Source IP must be RFC 5737 documentation range: ${ip}`);
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 10. Database Isolation (No WAF Event Table Pollution)
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Synthetic telemetry ticks NEVER insert into genuine waf_events table", async () => {
    const rawDb = new Database(TEST_DB_PATH);
    const countBefore = rawDb.prepare("SELECT count(*) as count FROM waf_events").get().count;

    // Run 30 synthetic cycles
    sim.config.attackIntensity = 0.5;
    for (let i = 0; i < 30; i++) {
      await sim.generateAndEmitLog();
    }

    const countAfter = rawDb.prepare("SELECT count(*) as count FROM waf_events").get().count;
    assert.strictEqual(countAfter, countBefore, "waf_events table must remain 100% clean of synthetic events");
    rawDb.close();
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 11. Incident Flooding Protection (Default OFF)
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Simulator creates 0 incidents by default when createIncidents = false", async () => {
    const rawDb = new Database(TEST_DB_PATH);
    const incidentsBefore = rawDb.prepare("SELECT count(*) as count FROM incidents").get().count;

    sim.config.createIncidents = false;
    sim.config.attackIntensity = 1.0; // 100% attacks

    for (let i = 0; i < 20; i++) {
      await sim.generateAndEmitLog();
    }

    const incidentsAfter = rawDb.prepare("SELECT count(*) as count FROM incidents").get().count;
    assert.strictEqual(incidentsAfter, incidentsBefore, "Incidents count must not increase when createIncidents = false");
    rawDb.close();
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 12. Throttled Demonstration Incidents (When Opted In)
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Demonstration incidents are strictly throttled (1 per 3s) and tagged SIMULATED", async () => {
    sim.config.createIncidents = true;
    sim.config.attackIntensity = 1.0;
    sim.lastIncidentCreationTime = 0; // Reset throttle

    // Rapidly generate 10 attacks in quick succession
    for (let i = 0; i < 10; i++) {
      await sim.generateAndEmitLog();
    }

    // Only 1 incident should have been created due to the 3-second throttle
    const rawDb = new Database(TEST_DB_PATH, { readonly: true });
    const simIncidents = rawDb.prepare("SELECT * FROM incidents WHERE eventSource = 'SIMULATED'").all();
    assert.strictEqual(simIncidents.length, 1, "Only 1 incident should pass throttle window");

    const created = simIncidents[0];
    assert.strictEqual(created.eventSource, "SIMULATED", "Must have eventSource = 'SIMULATED'");
    assert.strictEqual(created.assignedTo, "Simulator", "Must be assigned to 'Simulator'");
    assert.ok(created.description.includes("[SIMULATED]"), "Description must contain [SIMULATED] tag");

    rawDb.close();
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 13. Production Baseline Database Integrity
  // ─────────────────────────────────────────────────────────────────────────────
  await test("Production SQLite database retains exact baseline counts and structures", async () => {
    const prodDbPath = path.join(__dirname, "../backend/database.sqlite");
    assert.ok(fs.existsSync(prodDbPath), "Production database must exist");

    const prodDb = new Database(prodDbPath, { readonly: true });
    
    const wafCount = prodDb.prepare("SELECT count(*) as c FROM waf_events").get().c;
    const incCount = prodDb.prepare("SELECT count(*) as c FROM incidents").get().c;
    const campCount = prodDb.prepare("SELECT count(*) as c FROM attack_campaigns").get().c;
    const linksCount = prodDb.prepare("SELECT count(*) as c FROM campaign_events").get().c;

    assert.strictEqual(wafCount, 175, "Production waf_events must be exactly 175");
    assert.strictEqual(incCount, 29, "Production incidents must be exactly 29");
    assert.strictEqual(campCount, 7, "Production attack_campaigns must be exactly 7");
    assert.strictEqual(linksCount, 19, "Production campaign_events must be exactly 19");

    // Verify 0 synthetic pollution in production database
    const syntheticWaf = prodDb.prepare("SELECT count(*) as c FROM waf_events WHERE eventSource = 'SIMULATED'").get().c;
    assert.strictEqual(syntheticWaf, 0, "Production waf_events must have 0 synthetic records");

    prodDb.close();
  });

  // Cleanup isolated test database
  try {
    if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
    const wal = `${TEST_DB_PATH}-wal`;
    const shm = `${TEST_DB_PATH}-shm`;
    if (fs.existsSync(wal)) fs.unlinkSync(wal);
    if (fs.existsSync(shm)) fs.unlinkSync(shm);
  } catch (e) {}

  console.log("\n================================================================================");
  console.log(` RESULTS: ${passed}/${total} Simulator Tests Passed (${Math.round((passed/total)*100)}%)`);
  console.log("================================================================================\n");

  if (passed !== total) {
    process.exit(1);
  }
}

runSimulatorTestSuite().catch(err => {
  console.error("FATAL SUITE ERROR:", err);
  process.exit(1);
});
