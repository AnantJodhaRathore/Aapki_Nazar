const Database = require('better-sqlite3');
const path = require('path');
const riskEngine = require('./contextualRiskEngine');

const DB_FILE = process.env.SQLITE_DB_PATH || path.join(__dirname, '../database.sqlite');
const db = new Database(DB_FILE, { 
  verbose: process.env.DEBUG_SQL === "true" ? console.log : undefined 
});
db.pragma('journal_mode = WAL'); // Better performance and concurrency

// Initialize Database Tables
function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS incidents (
      incidentId TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      assignedTo TEXT NOT NULL,
      slaDeadline TEXT NOT NULL,
      escalated BOOLEAN NOT NULL DEFAULT 0,
      timeline TEXT NOT NULL,
      playbook TEXT,
      payload TEXT,
      comments TEXT,
      rootCause TEXT,
      extractedPayload TEXT,
      confidence TEXT,
      threatType TEXT,
      mitreTechnique TEXT,
      hash TEXT,
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL,
      resolvedAt TEXT
    );
  `);

  try {
    db.exec(`ALTER TABLE incidents ADD COLUMN resolvedAt TEXT;`);
  } catch (err) {
    // Column might already exist
  }

  try {
    db.exec(`ALTER TABLE incidents ADD COLUMN eventSource TEXT DEFAULT 'CUSTOM_WAF';`);
  } catch (err) {
    // Column might already exist
  }

  try {
    db.exec(`ALTER TABLE incidents ADD COLUMN wafTransactionId TEXT;`);
  } catch (err) {
    // Column might already exist
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS waf_events (
      id TEXT PRIMARY KEY,
      transactionId TEXT UNIQUE,
      timestamp TEXT NOT NULL,
      clientIp TEXT NOT NULL,
      simulatedClientIp TEXT,
      simulatedSessionId TEXT,
      method TEXT NOT NULL,
      uri TEXT NOT NULL,
      httpCode INTEGER NOT NULL,
      action TEXT NOT NULL,
      blocked BOOLEAN NOT NULL DEFAULT 0,
      anomalyScore INTEGER DEFAULT 0,
      primaryRuleId TEXT,
      primaryRuleMsg TEXT,
      category TEXT,
      severity TEXT NOT NULL,
      tags TEXT,
      messages TEXT,
      rawTransaction TEXT,
      incidentId TEXT,
      eventSource TEXT NOT NULL DEFAULT 'OFFICIAL_CRS',
      createdAt TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_waf_events_tx ON waf_events(transactionId);
    CREATE INDEX IF NOT EXISTS idx_waf_events_time ON waf_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_waf_events_incident ON waf_events(incidentId);
  `);

  try {
    db.exec(`ALTER TABLE waf_events ADD COLUMN simulatedClientIp TEXT;`);
  } catch (err) {
    // Column might already exist
  }

  try {
    db.exec(`ALTER TABLE waf_events ADD COLUMN category TEXT;`);
  } catch (err) {
    // Column might already exist
  }

  try {
    db.exec(`ALTER TABLE waf_events ADD COLUMN simulatedSessionId TEXT;`);
  } catch (err) {
    // Column might already exist
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      targetId TEXT,
      details TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_quarantine (
      id TEXT PRIMARY KEY,
      rawRecord TEXT,
      reason TEXT,
      offset INTEGER,
      timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_quarantine_time ON audit_quarantine(timestamp);

    CREATE TABLE IF NOT EXISTS attack_campaigns (
      id TEXT PRIMARY KEY,
      correlationKey TEXT NOT NULL,
      identityType TEXT NOT NULL,
      firstSeen TEXT NOT NULL,
      lastSeen TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      eventCount INTEGER NOT NULL DEFAULT 1,
      blockedCount INTEGER NOT NULL DEFAULT 0,
      riskScore INTEGER NOT NULL DEFAULT 0,
      riskLevel TEXT NOT NULL DEFAULT 'LOW',
      incidentId TEXT,
      targetEndpoints TEXT,
      attackCategories TEXT,
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_campaigns_key ON attack_campaigns(correlationKey);
    CREATE INDEX IF NOT EXISTS idx_campaigns_status ON attack_campaigns(status);
    CREATE INDEX IF NOT EXISTS idx_campaigns_lastseen ON attack_campaigns(lastSeen);

    CREATE TABLE IF NOT EXISTS campaign_events (
      id TEXT PRIMARY KEY,
      campaignId TEXT NOT NULL,
      wafEventId TEXT NOT NULL,
      eventTimestamp TEXT NOT NULL,
      riskScoreAfterEvent INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_camp_events_camp ON campaign_events(campaignId);

    CREATE TABLE IF NOT EXISTS campaign_risk_explanations (
      campaignId TEXT PRIMARY KEY,
      severityScore INTEGER NOT NULL,
      frequencyScore INTEGER NOT NULL,
      diversityScore INTEGER NOT NULL,
      persistenceScore INTEGER NOT NULL,
      targetScore INTEGER NOT NULL,
      explanationJson TEXT NOT NULL,
      updatedAt TEXT NOT NULL
    );
  `);

  // Apply unique index on wafEventId if no duplicates, otherwise reconciliation will apply it
  try {
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_camp_events_unique_waf ON campaign_events(wafEventId);`);
  } catch (idxErr) {
    // Expected during initial migration if duplicates exist in campaign_events
  }
}

function resetDatabase() {
  const resetTx = db.transaction(() => {
    db.prepare("DELETE FROM incidents").run();
    db.prepare("DELETE FROM audit_logs").run();
    db.prepare("DELETE FROM waf_events").run();
    db.prepare("DELETE FROM attack_campaigns").run();
    db.prepare("DELETE FROM campaign_events").run();
    db.prepare("DELETE FROM campaign_risk_explanations").run();
  });

  resetTx();
  try {
    db.pragma('wal_checkpoint(TRUNCATE)');
  } catch (err) {
    console.warn("WAL checkpoint warning:", err.message);
  }
  return { success: true, count: 0 };
}

initDb();

// Helper to format rows from DB back to API JSON structure
function formatRow(row, auditLogs = []) {
  if (!row) return null;
  return {
    ...row,
    escalated: !!row.escalated,
    timeline: auditLogs.length > 0 ? auditLogs : JSON.parse(row.timeline || '[]'), // prefer relational audit logs
    playbook: row.playbook ? JSON.parse(row.playbook) : null,
    payload: row.payload ? JSON.parse(row.payload) : null,
    comments: row.comments ? JSON.parse(row.comments) : [],
    rootCause: row.rootCause,
    extractedPayload: row.extractedPayload,
    confidence: row.confidence,
    threatType: row.threatType,
    mitreTechnique: row.mitreTechnique ? JSON.parse(row.mitreTechnique) : null,
    hash: row.hash,
    resolvedAt: row.resolvedAt,
    eventSource: row.eventSource || (row.assignedTo === 'OWASP-CRS-Engine' ? 'OFFICIAL_CRS' : 'CUSTOM_WAF'),
    wafTransactionId: row.wafTransactionId || null
  };
}

function fetchAuditLogs(id) {
  const rows = db.prepare("SELECT * FROM audit_logs WHERE targetId = ? ORDER BY timestamp ASC").all(id);
  return rows.map(r => ({
    timestamp: r.timestamp,
    action: r.action,
    by: r.actor,
    note: r.details || ""
  }));
}

async function getAllIncidents() {
  const rows = db.prepare("SELECT * FROM incidents ORDER BY createdAt DESC").all();
  return rows.map(row => formatRow(row, fetchAuditLogs(row.incidentId)));
}

async function getIncidentById(id) {
  const row = db.prepare("SELECT * FROM incidents WHERE incidentId = ?").get(id);
  return formatRow(row, fetchAuditLogs(id));
}

async function createIncident(data) {
  const now = new Date().toISOString();
  const insert = db.prepare(`
    INSERT INTO incidents (incidentId, title, description, severity, status, assignedTo, slaDeadline, escalated, timeline, playbook, payload, comments, rootCause, extractedPayload, confidence, threatType, mitreTechnique, hash, createdAt, updatedAt, resolvedAt, eventSource, wafTransactionId)
    VALUES (@incidentId, @title, @description, @severity, @status, @assignedTo, @slaDeadline, @escalated, @timeline, @playbook, @payload, @comments, @rootCause, @extractedPayload, @confidence, @threatType, @mitreTechnique, @hash, @createdAt, @updatedAt, @resolvedAt, @eventSource, @wafTransactionId)
  `);

  const item = {
    incidentId: data.incidentId,
    title: data.title,
    description: data.description || '',
    severity: data.severity,
    status: data.status,
    assignedTo: data.assignedTo,
    slaDeadline: data.slaDeadline,
    escalated: data.escalated ? 1 : 0,
    timeline: JSON.stringify(data.timeline || []),
    playbook: data.playbook ? JSON.stringify(data.playbook) : null,
    payload: data.payload ? JSON.stringify(data.payload) : null,
    comments: JSON.stringify(data.comments || []),
    rootCause: data.rootCause || null,
    extractedPayload: data.extractedPayload || null,
    confidence: data.confidence || null,
    threatType: data.threatType || null,
    mitreTechnique: data.mitreTechnique ? JSON.stringify(data.mitreTechnique) : null,
    hash: data.hash || null,
    createdAt: data.createdAt || now,
    updatedAt: data.updatedAt || now,
    resolvedAt: data.resolvedAt || null,
    eventSource: data.eventSource || (data.assignedTo === 'OWASP-CRS-Engine' ? 'OFFICIAL_CRS' : 'CUSTOM_WAF'),
    wafTransactionId: data.wafTransactionId || null
  };

  insert.run(item);
  return formatRow(item);
}

async function updateIncident(id, updates) {
  const existing = await getIncidentById(id);
  if (!existing) return null;

  const merged = { ...existing, ...updates };
  merged.updatedAt = new Date().toISOString();

  const update = db.prepare(`
    UPDATE incidents SET 
      title = @title,
      description = @description,
      severity = @severity,
      status = @status,
      assignedTo = @assignedTo,
      slaDeadline = @slaDeadline,
      escalated = @escalated,
      timeline = @timeline,
      playbook = @playbook,
      payload = @payload,
      comments = @comments,
      rootCause = @rootCause,
      extractedPayload = @extractedPayload,
      confidence = @confidence,
      threatType = @threatType,
      mitreTechnique = @mitreTechnique,
      hash = @hash,
      updatedAt = @updatedAt,
      resolvedAt = @resolvedAt,
      eventSource = @eventSource,
      wafTransactionId = @wafTransactionId
    WHERE incidentId = @incidentId
  `);

  update.run({
    title: merged.title,
    description: merged.description || '',
    severity: merged.severity,
    status: merged.status,
    assignedTo: merged.assignedTo,
    slaDeadline: merged.slaDeadline,
    escalated: merged.escalated ? 1 : 0,
    timeline: JSON.stringify(merged.timeline || []),
    playbook: merged.playbook ? JSON.stringify(merged.playbook) : null,
    payload: merged.payload ? JSON.stringify(merged.payload) : null,
    comments: JSON.stringify(merged.comments || []),
    rootCause: merged.rootCause || null,
    extractedPayload: merged.extractedPayload || null,
    confidence: merged.confidence || null,
    threatType: merged.threatType || null,
    mitreTechnique: merged.mitreTechnique ? JSON.stringify(merged.mitreTechnique) : null,
    hash: merged.hash || null,
    updatedAt: merged.updatedAt,
    resolvedAt: merged.resolvedAt || null,
    eventSource: merged.eventSource || 'CUSTOM_WAF',
    wafTransactionId: merged.wafTransactionId || null,
    incidentId: id
  });

  return merged;
}

async function updateIncidentStatus(id, status) {
  return updateIncident(id, { status });
}

async function deleteIncident(id) {
  const result = db.prepare("DELETE FROM incidents WHERE incidentId = ?").run(id);
  return result.changes > 0;
}

async function logAuditAction(action, actor, targetId, details) {
  const insert = db.prepare(`
    INSERT INTO audit_logs (id, action, actor, targetId, details, timestamp)
    VALUES (@id, @action, @actor, @targetId, @details, @timestamp)
  `);
  
  insert.run({
    id: "AUD-" + Date.now() + "-" + Math.floor(Math.random() * 1000),
    action,
    actor,
    targetId: targetId || null,
    details: details ? JSON.stringify(details) : null,
    timestamp: new Date().toISOString()
  });
}

// ── WAF EVENTS PERSISTENCE (GENUINE CRS & SENSOR EVENTS) ──

function deriveCategory(r) {
  if (r && r.category && r.category !== 'Web Anomaly' && r.category !== 'OWASP CRS Detection') {
    return r.category;
  }
  return riskEngine.deriveCategory(r);
}

function isEventEligible(e) {
  return riskEngine.isEventEligible(e);
}

function formatWafEventRow(row) {
  if (!row) return null;
  return {
    ...row,
    category: row.category || deriveCategory(row),
    simulatedClientIp: row.simulatedClientIp || null,
    simulatedSessionId: row.simulatedSessionId || null,
    blocked: !!row.blocked,
    tags: row.tags ? (typeof row.tags === 'string' ? JSON.parse(row.tags) : row.tags) : [],
    messages: row.messages ? (typeof row.messages === 'string' ? JSON.parse(row.messages) : row.messages) : [],
    rawTransaction: row.rawTransaction ? (typeof row.rawTransaction === "string" ? JSON.parse(row.rawTransaction) : row.rawTransaction) : null
  };
}

async function createWafEvent(data) {
  const now = new Date().toISOString();
  const id = data.id || `WAF-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const derivedCat = data.category || deriveCategory(data);

  const insert = db.prepare(`
    INSERT OR IGNORE INTO waf_events (
      id, transactionId, timestamp, clientIp, simulatedClientIp, simulatedSessionId, method, uri, httpCode, action, blocked,
      anomalyScore, primaryRuleId, primaryRuleMsg, category, severity, tags, messages, rawTransaction,
      incidentId, eventSource, createdAt
    ) VALUES (
      @id, @transactionId, @timestamp, @clientIp, @simulatedClientIp, @simulatedSessionId, @method, @uri, @httpCode, @action, @blocked,
      @anomalyScore, @primaryRuleId, @primaryRuleMsg, @category, @severity, @tags, @messages, @rawTransaction,
      @incidentId, @eventSource, @createdAt
    )
  `);

  const item = {
    id,
    transactionId: data.transactionId || id,
    timestamp: data.timestamp || now,
    clientIp: data.clientIp || "127.0.0.1",
    simulatedClientIp: data.simulatedClientIp || null,
    simulatedSessionId: data.simulatedSessionId || null,
    method: data.method || "GET",
    uri: data.uri || "/",
    httpCode: data.httpCode || 200,
    action: data.action || (data.blocked ? "BLOCKED" : "ALLOWED"),
    blocked: data.blocked ? 1 : 0,
    anomalyScore: data.anomalyScore || 0,
    primaryRuleId: data.primaryRuleId || null,
    primaryRuleMsg: data.primaryRuleMsg || null,
    category: derivedCat,
    severity: data.severity || "LOW",
    tags: JSON.stringify(data.tags || []),
    messages: JSON.stringify(data.messages || []),
    rawTransaction: data.rawTransaction ? (typeof data.rawTransaction === "string" ? data.rawTransaction : JSON.stringify(data.rawTransaction)) : null,
    incidentId: data.incidentId || null,
    eventSource: data.eventSource || "OFFICIAL_CRS",
    createdAt: data.createdAt || now
  };

  insert.run(item);
  return formatWafEventRow(item);
}

async function quarantineRecord(data) {
  const id = `QRT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const insert = db.prepare(`
    INSERT INTO audit_quarantine (id, rawRecord, reason, offset, timestamp)
    VALUES (@id, @rawRecord, @reason, @offset, @timestamp)
  `);
  insert.run({
    id,
    rawRecord: typeof data.rawRecord === 'string' ? data.rawRecord : JSON.stringify(data.rawRecord || {}),
    reason: data.reason || 'Malformed JSON',
    offset: Number(data.offset) || 0,
    timestamp: new Date().toISOString()
  });
  return { id, ...data };
}

async function getQuarantineRecords(limit = 100) {
  const rows = db.prepare("SELECT * FROM audit_quarantine ORDER BY timestamp DESC LIMIT ?").all(limit);
  return rows;
}

async function getWafEventByTransactionId(txId) {
  const row = db.prepare("SELECT * FROM waf_events WHERE transactionId = ?").get(txId);
  return formatWafEventRow(row);
}

async function getAllWafEvents(limit = 100, filter = {}) {
  let query = "SELECT * FROM waf_events";
  const conditions = [];
  const params = [];

  if (filter.blocked !== undefined) {
    conditions.push("blocked = ?");
    params.push(filter.blocked ? 1 : 0);
  }
  if (filter.eventSource) {
    conditions.push("eventSource = ?");
    params.push(filter.eventSource);
  }
  if (filter.clientIp) {
    conditions.push("clientIp = ?");
    params.push(filter.clientIp);
  }

  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY timestamp DESC LIMIT ?";
  params.push(limit);

  const rows = db.prepare(query).all(...params);
  return rows.map(formatWafEventRow);
}

async function getWafStats() {
  const total = db.prepare("SELECT count(*) as count FROM waf_events").get()?.count || 0;
  const blocked = db.prepare("SELECT count(*) as count FROM waf_events WHERE blocked = 1").get()?.count || 0;
  const allowed = db.prepare("SELECT count(*) as count FROM waf_events WHERE blocked = 0").get()?.count || 0;
  const crsEvents = db.prepare("SELECT count(*) as count FROM waf_events WHERE eventSource = 'OFFICIAL_CRS'").get()?.count || 0;
  return {
    totalEvents: total,
    totalBlocked: blocked,
    totalAllowed: allowed,
    crsEventsCount: crsEvents
  };
}

async function linkWafEventToIncident(transactionId, incidentId) {
  db.prepare("UPDATE waf_events SET incidentId = ? WHERE transactionId = ?").run(incidentId, transactionId);
  try {
    db.prepare("UPDATE incidents SET wafTransactionId = ? WHERE incidentId = ?").run(transactionId, incidentId);
  } catch (e) {}
}

// ── ATTACK CAMPAIGNS PERSISTENCE (PHASE 2 CORRELATION & EXPLAINABILITY) ──

function formatCampaignRow(row) {
  if (!row) return null;
  return {
    ...row,
    eventCount: Number(row.eventCount) || 0,
    blockedCount: Number(row.blockedCount) || 0,
    riskScore: Number(row.riskScore) || 0,
    targetEndpoints: row.targetEndpoints ? (typeof row.targetEndpoints === 'string' ? JSON.parse(row.targetEndpoints) : row.targetEndpoints) : [],
    attackCategories: row.attackCategories ? (typeof row.attackCategories === 'string' ? JSON.parse(row.attackCategories) : row.attackCategories) : []
  };
}

async function getActiveCampaignByKey(correlationKey) {
  const row = db.prepare(
    "SELECT * FROM attack_campaigns WHERE correlationKey = ? AND status = 'ACTIVE' ORDER BY lastSeen DESC LIMIT 1"
  ).get(correlationKey);
  return formatCampaignRow(row);
}

async function getCampaignById(id) {
  const row = db.prepare("SELECT * FROM attack_campaigns WHERE id = ?").get(id);
  return formatCampaignRow(row);
}

async function getAllCampaigns(filters = {}) {
  let query = "SELECT * FROM attack_campaigns";
  const conditions = [];
  const params = [];

  if (filters.status) {
    conditions.push("status = ?");
    params.push(filters.status);
  }
  if (filters.riskLevel) {
    conditions.push("riskLevel = ?");
    params.push(filters.riskLevel);
  }
  if (filters.identityType) {
    conditions.push("identityType = ?");
    params.push(filters.identityType);
  }

  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }

  query += " ORDER BY lastSeen DESC";

  if (filters.limit) {
    query += " LIMIT ?";
    params.push(Number(filters.limit));
  }

  const rows = db.prepare(query).all(...params);
  return rows.map(formatCampaignRow);
}

async function createCampaign(data) {
  const now = new Date().toISOString();
  const id = data.id || `CAMP-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

  const insert = db.prepare(`
    INSERT INTO attack_campaigns (
      id, correlationKey, identityType, firstSeen, lastSeen, status,
      eventCount, blockedCount, riskScore, riskLevel, incidentId,
      targetEndpoints, attackCategories, createdAt, updatedAt
    ) VALUES (
      @id, @correlationKey, @identityType, @firstSeen, @lastSeen, @status,
      @eventCount, @blockedCount, @riskScore, @riskLevel, @incidentId,
      @targetEndpoints, @attackCategories, @createdAt, @updatedAt
    )
  `);

  const item = {
    id,
    correlationKey: data.correlationKey,
    identityType: data.identityType || "REAL_NETWORK_IP",
    firstSeen: data.firstSeen || now,
    lastSeen: data.lastSeen || now,
    status: data.status || "ACTIVE",
    eventCount: Number(data.eventCount) || 1,
    blockedCount: Number(data.blockedCount) || 0,
    riskScore: Number(data.riskScore) || 0,
    riskLevel: data.riskLevel || "LOW",
    incidentId: data.incidentId || null,
    targetEndpoints: JSON.stringify(data.targetEndpoints || []),
    attackCategories: JSON.stringify(data.attackCategories || []),
    createdAt: data.createdAt || now,
    updatedAt: data.updatedAt || now
  };

  insert.run(item);
  return formatCampaignRow(item);
}

async function updateCampaign(id, updates) {
  const existing = await getCampaignById(id);
  if (!existing) return null;

  const merged = { ...existing, ...updates };
  merged.updatedAt = new Date().toISOString();

  // Strict monotonic timestamp bounds: firstSeen <= lastSeen always
  let finalFirstSeen = existing.firstSeen;
  let finalLastSeen = existing.lastSeen;
  if (updates.firstSeen && new Date(updates.firstSeen).getTime() < new Date(finalFirstSeen).getTime()) {
    finalFirstSeen = updates.firstSeen;
  }
  if (updates.lastSeen && new Date(updates.lastSeen).getTime() > new Date(finalLastSeen).getTime()) {
    finalLastSeen = updates.lastSeen;
  }
  if (new Date(finalFirstSeen).getTime() > new Date(finalLastSeen).getTime()) {
    finalFirstSeen = finalLastSeen;
  }

  merged.firstSeen = finalFirstSeen;
  merged.lastSeen = finalLastSeen;

  const update = db.prepare(`
    UPDATE attack_campaigns SET
      firstSeen = @firstSeen,
      lastSeen = @lastSeen,
      status = @status,
      eventCount = @eventCount,
      blockedCount = @blockedCount,
      riskScore = @riskScore,
      riskLevel = @riskLevel,
      incidentId = @incidentId,
      targetEndpoints = @targetEndpoints,
      attackCategories = @attackCategories,
      updatedAt = @updatedAt
    WHERE id = @id
  `);

  update.run({
    id,
    firstSeen: merged.firstSeen,
    lastSeen: merged.lastSeen,
    status: merged.status,
    eventCount: Number(merged.eventCount) || 1,
    blockedCount: Number(merged.blockedCount) || 0,
    riskScore: Number(merged.riskScore) || 0,
    riskLevel: merged.riskLevel,
    incidentId: merged.incidentId || null,
    targetEndpoints: JSON.stringify(merged.targetEndpoints || []),
    attackCategories: JSON.stringify(merged.attackCategories || []),
    updatedAt: merged.updatedAt
  });

  return formatCampaignRow(merged);
}

async function addCampaignEvent(data) {
  const id = data.id || `CEVT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const insert = db.prepare(`
    INSERT INTO campaign_events (id, campaignId, wafEventId, eventTimestamp, riskScoreAfterEvent)
    VALUES (@id, @campaignId, @wafEventId, @eventTimestamp, @riskScoreAfterEvent)
    ON CONFLICT(wafEventId) DO UPDATE SET
      riskScoreAfterEvent = excluded.riskScoreAfterEvent
  `);

  insert.run({
    id,
    campaignId: data.campaignId,
    wafEventId: data.wafEventId,
    eventTimestamp: data.eventTimestamp || new Date().toISOString(),
    riskScoreAfterEvent: Number(data.riskScoreAfterEvent) || 0
  });

  return { id, ...data };
}

async function getCampaignEventByWafId(wafEventId) {
  const row = db.prepare("SELECT * FROM campaign_events WHERE wafEventId = ? LIMIT 1").get(wafEventId);
  return row || null;
}

async function getCampaignByWafEventId(wafEventId) {
  const row = db.prepare(`
    SELECT c.* FROM attack_campaigns c
    JOIN campaign_events ce ON c.id = ce.campaignId
    WHERE ce.wafEventId = ?
    LIMIT 1
  `).get(wafEventId);
  return formatCampaignRow(row);
}

async function getCampaignEvents(campaignId) {
  // Join campaign_events with waf_events to provide complete event detail along with chronological risk progression
  const rows = db.prepare(`
    SELECT ce.id as campaignEventId, ce.campaignId, ce.wafEventId, ce.eventTimestamp, ce.riskScoreAfterEvent,
           we.transactionId, we.clientIp, we.simulatedClientIp, we.method, we.uri, we.httpCode,
           we.action, we.blocked, we.anomalyScore, we.primaryRuleId, we.primaryRuleMsg,
           we.severity, we.tags, we.messages, we.incidentId, we.eventSource
    FROM campaign_events ce
    LEFT JOIN waf_events we ON ce.wafEventId = we.id OR ce.wafEventId = we.transactionId
    WHERE ce.campaignId = ?
    ORDER BY ce.eventTimestamp ASC
  `).all(campaignId);

  return rows.map(r => ({
    campaignEventId: r.campaignEventId,
    campaignId: r.campaignId,
    wafEventId: r.wafEventId,
    timestamp: r.eventTimestamp,
    riskScoreAfterEvent: r.riskScoreAfterEvent,
    transactionId: r.transactionId,
    clientIp: r.clientIp,
    simulatedClientIp: r.simulatedClientIp,
    method: r.method,
    uri: r.uri,
    httpCode: r.httpCode,
    action: r.action,
    blocked: !!r.blocked,
    anomalyScore: r.anomalyScore,
    primaryRuleId: r.primaryRuleId,
    primaryRuleMsg: r.primaryRuleMsg,
    severity: r.severity,
    tags: r.tags ? (typeof r.tags === 'string' ? JSON.parse(r.tags) : r.tags) : [],
    messages: r.messages ? (typeof r.messages === 'string' ? JSON.parse(r.messages) : r.messages) : [],
    incidentId: r.incidentId,
    eventSource: r.eventSource
  }));
}

async function saveCampaignRiskExplanation(data) {
  const insert = db.prepare(`
    INSERT INTO campaign_risk_explanations (
      campaignId, severityScore, frequencyScore, diversityScore, persistenceScore, targetScore, explanationJson, updatedAt
    ) VALUES (
      @campaignId, @severityScore, @frequencyScore, @diversityScore, @persistenceScore, @targetScore, @explanationJson, @updatedAt
    )
    ON CONFLICT(campaignId) DO UPDATE SET
      severityScore = excluded.severityScore,
      frequencyScore = excluded.frequencyScore,
      diversityScore = excluded.diversityScore,
      persistenceScore = excluded.persistenceScore,
      targetScore = excluded.targetScore,
      explanationJson = excluded.explanationJson,
      updatedAt = excluded.updatedAt
  `);

  const item = {
    campaignId: data.campaignId,
    severityScore: Number(data.severityScore) || 0,
    frequencyScore: Number(data.frequencyScore) || 0,
    diversityScore: Number(data.diversityScore) || 0,
    persistenceScore: Number(data.persistenceScore) || 0,
    targetScore: Number(data.targetScore) || 0,
    explanationJson: typeof data.explanationJson === 'string' ? data.explanationJson : JSON.stringify(data.explanationJson || {}),
    updatedAt: new Date().toISOString()
  };

  insert.run(item);
  return {
    ...item,
    explanationJson: JSON.parse(item.explanationJson)
  };
}

async function getCampaignRiskExplanation(campaignId) {
  const row = db.prepare("SELECT * FROM campaign_risk_explanations WHERE campaignId = ?").get(campaignId);
  if (!row) return null;
  return {
    ...row,
    explanationJson: row.explanationJson ? JSON.parse(row.explanationJson) : {}
  };
}

async function getCampaignStats() {
  const totalWafEvents = db.prepare("SELECT count(*) as count FROM waf_events").get()?.count || 0;
  
  // Eligible suspicious transactions: blocked = 1 OR anomalyScore >= 5 (excluding benign protocol warning)
  const eligibleWafEvents = db.prepare(`
    SELECT count(*) as count FROM waf_events
    WHERE blocked = 1 OR (anomalyScore >= 5 AND (
      category != 'Protocol Validation' AND category != 'Web Anomaly'
    ))
  `).get()?.count || 0;

  const excludedWafEvents = Math.max(0, totalWafEvents - eligibleWafEvents);

  // Distinct WAF events actually linked to a campaign (unique correlated events)
  const uniqueCorrelatedEvents = db.prepare("SELECT count(distinct wafEventId) as count FROM campaign_events").get()?.count || 0;

  const totalCampaigns = db.prepare("SELECT count(*) as count FROM attack_campaigns").get()?.count || 0;
  const activeCampaigns = db.prepare("SELECT count(*) as count FROM attack_campaigns WHERE status = 'ACTIVE'").get()?.count || 0;
  const closedCampaigns = db.prepare("SELECT count(*) as count FROM attack_campaigns WHERE status = 'CLOSED'").get()?.count || 0;
  const mitigatedCampaigns = db.prepare("SELECT count(*) as count FROM attack_campaigns WHERE status = 'MITIGATED'").get()?.count || 0;
  const highRiskCampaigns = db.prepare("SELECT count(*) as count FROM attack_campaigns WHERE riskLevel IN ('HIGH', 'CRITICAL')").get()?.count || 0;
  const criticalRiskCampaigns = db.prepare("SELECT count(*) as count FROM attack_campaigns WHERE riskLevel = 'CRITICAL'").get()?.count || 0;

  const avgScoreRow = db.prepare("SELECT AVG(riskScore) as avgScore FROM attack_campaigns").get();
  const avgRiskScore = avgScoreRow && avgScoreRow.avgScore !== null ? Math.round(avgScoreRow.avgScore) : 0;

  const consolidationRatio = eligibleWafEvents > 0 
    ? Number((eligibleWafEvents / Math.max(1, totalCampaigns)).toFixed(1))
    : 1.0;

  const consolidationPercent = eligibleWafEvents > 0
    ? Math.round(((eligibleWafEvents - totalCampaigns) / eligibleWafEvents) * 100)
    : 0;

  const unlinkedEligibleEvents = Math.max(0, eligibleWafEvents - uniqueCorrelatedEvents);
  const dynamicExclusionNote = `${excludedWafEvents} low-severity unblocked protocol warnings (Rule 920350, HTTP 200, Anomaly Score 0) preserved in audit log but excluded from attack campaigns`;

  return {
    totalWafEvents,
    eligibleWafEvents,
    excludedWafEvents,
    uniqueCorrelatedEvents,
    unlinkedEligibleEvents,
    pendingRecoveryCount: unlinkedEligibleEvents,
    totalCampaigns,
    activeCampaigns,
    closedCampaigns,
    mitigatedCampaigns,
    highRiskCampaigns,
    criticalRiskCampaigns,
    avgRiskScore,
    consolidationRatio,
    consolidationPercent,
    reductionPercent: consolidationPercent,
    totalRawEvents: totalWafEvents,
    totalCorrelatedEvents: uniqueCorrelatedEvents,
    comparisonMetric: "Eligible WAF Events vs Distinct Correlated Campaigns",
    exclusionNote: dynamicExclusionNote
  };
}

function reconcileDatabaseCampaigns(force = false) {
  const WINDOW_MS = 10 * 60 * 1000;

  const tx = db.transaction(() => {
    // 1. Ensure category column and populate on waf_events
    const allWafEvents = db.prepare("SELECT * FROM waf_events ORDER BY timestamp ASC").all();
    const updateCatStmt = db.prepare("UPDATE waf_events SET category = ? WHERE id = ?");
    for (const ev of allWafEvents) {
      ev.category = deriveCategory(ev);
      updateCatStmt.run(ev.category, ev.id);
    }

    const eligibleEvents = allWafEvents.filter(isEventEligible);

    // 2. Check for missing eligible links, duplicates, or orphans
    const linkedEventRows = db.prepare("SELECT wafEventId FROM campaign_events").all();
    const linkedWafIds = new Set(linkedEventRows.map(r => r.wafEventId));
    const unlinkedEligible = eligibleEvents.filter(e => !linkedWafIds.has(e.id) && !linkedWafIds.has(e.transactionId));

    let duplicateLinks = 0;
    try {
      duplicateLinks = db.prepare("SELECT count(*) as c FROM (SELECT wafEventId FROM campaign_events GROUP BY wafEventId HAVING count(*) > 1)").get()?.c || 0;
    } catch (e) {}

    let orphanLinks = 0;
    try {
      orphanLinks = db.prepare("SELECT count(*) as c FROM campaign_events WHERE wafEventId NOT IN (SELECT id FROM waf_events UNION SELECT transactionId FROM waf_events)").get()?.c || 0;
    } catch (e) {}

    const hasCampaigns = db.prepare("SELECT count(*) as c FROM attack_campaigns").get()?.c || 0;

    // Check if existing campaign scores differ from authoritative recalculation
    let scoresDivergent = false;
    if (hasCampaigns > 0 && unlinkedEligible.length === 0 && duplicateLinks === 0 && orphanLinks === 0) {
      const sampleCampaigns = db.prepare("SELECT id, riskScore FROM attack_campaigns").all();
      for (const sc of sampleCampaigns) {
        const ce = db.prepare(`
          SELECT w.* FROM waf_events w 
          JOIN campaign_events ce ON (w.id = ce.wafEventId OR w.transactionId = ce.wafEventId) 
          WHERE ce.campaignId = ? 
          ORDER BY w.timestamp ASC
        `).all(sc.id);
        if (ce.length > 0) {
          const expectedScore = riskEngine.calculateContextualRisk(ce).riskScore;
          if (expectedScore !== sc.riskScore) {
            scoresDivergent = true;
            break;
          }
        }
      }
    }

    const needsRebuild = force || duplicateLinks > 0 || orphanLinks > 0 || unlinkedEligible.length > 0 || (hasCampaigns === 0 && eligibleEvents.length > 0) || scoresDivergent;

    if (needsRebuild) {
      // Map existing campaign membership to preserve stable IDs, mitigated status, and incident links
      const existingCampaigns = db.prepare("SELECT * FROM attack_campaigns").all();
      const existingLinks = db.prepare("SELECT campaignId, wafEventId FROM campaign_events").all();
      const eventToCampMap = new Map();
      for (const l of existingLinks) {
        eventToCampMap.set(l.wafEventId, l.campaignId);
      }
      const campRecordMap = new Map();
      for (const c of existingCampaigns) {
        campRecordMap.set(c.id, c);
      }

      db.exec(`
        DROP TABLE IF EXISTS campaign_events;
        CREATE TABLE campaign_events (
          id TEXT PRIMARY KEY,
          campaignId TEXT NOT NULL,
          wafEventId TEXT NOT NULL UNIQUE,
          eventTimestamp TEXT NOT NULL,
          riskScoreAfterEvent INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX idx_camp_events_unique_waf ON campaign_events(wafEventId);
        CREATE INDEX idx_camp_events_camp ON campaign_events(campaignId);

        DELETE FROM campaign_risk_explanations;
        DELETE FROM attack_campaigns;
      `);

      const campaigns = [];

      for (const ev of eligibleEvents) {
        const simIp = ev.simulatedClientIp;
        const simSession = ev.simulatedSessionId;
        let correlationKey = '';
        let identityType = 'REAL_NETWORK_IP';
        if (simSession) {
          identityType = 'SIMULATION_SESSION';
          correlationKey = `SIM:${simIp}:${simSession}`;
        } else if (simIp) {
          identityType = 'SIMULATION_SESSION';
          correlationKey = `SIM:${simIp}:legacy`;
        } else {
          correlationKey = `REAL:${ev.clientIp || '127.0.0.1'}`;
        }

        const evTime = new Date(ev.timestamp).getTime();
        let camp = campaigns.find(c => c.correlationKey === correlationKey && c.status === 'ACTIVE');
        if (camp) {
          const lastTime = new Date(camp.lastSeen).getTime();
          if (evTime - lastTime > WINDOW_MS) {
            camp.status = 'CLOSED';
            camp = null;
          }
        }

        if (!camp) {
          // Identify if an existing stable campaign ID can be preserved
          let preservedId = null;
          let preservedStatus = null;
          let preservedIncidentId = null;

          // Check if this specific event was already linked to an existing campaign
          const prevCampId = eventToCampMap.get(ev.id) || eventToCampMap.get(ev.transactionId);
          if (prevCampId && campRecordMap.has(prevCampId)) {
            const rec = campRecordMap.get(prevCampId);
            if (rec.correlationKey === correlationKey) {
              preservedId = rec.id;
              preservedStatus = rec.status;
              preservedIncidentId = rec.incidentId;
            }
          }

          // Fallback: check matching key and start time
          if (!preservedId) {
            for (const rec of existingCampaigns) {
              if (rec.correlationKey === correlationKey && Math.abs(new Date(rec.firstSeen).getTime() - evTime) < 60000) {
                if (!campaigns.some(c => c.id === rec.id)) {
                  preservedId = rec.id;
                  preservedStatus = rec.status;
                  preservedIncidentId = rec.incidentId;
                  break;
                }
              }
            }
          }

          const campId = preservedId || `CAMP-${(campaigns.length + 1)}-${Math.floor(Math.random() * 1000)}`;
          camp = {
            id: campId,
            correlationKey,
            identityType,
            firstSeen: ev.timestamp,
            lastSeen: ev.timestamp,
            status: preservedStatus === 'MITIGATED' ? 'MITIGATED' : 'ACTIVE',
            events: [],
            incidentId: preservedIncidentId || ev.incidentId || null
          };
          campaigns.push(camp);
        }

        camp.events.push(ev);
        if (!camp.incidentId && ev.incidentId) {
          camp.incidentId = ev.incidentId;
        }

        if (new Date(ev.timestamp).getTime() < new Date(camp.firstSeen).getTime()) {
          camp.firstSeen = ev.timestamp;
        }
        if (new Date(ev.timestamp).getTime() > new Date(camp.lastSeen).getTime()) {
          camp.lastSeen = ev.timestamp;
        }
      }

      const insertCamp = db.prepare(`
        INSERT INTO attack_campaigns (
          id, correlationKey, identityType, firstSeen, lastSeen, status,
          eventCount, blockedCount, riskScore, riskLevel, incidentId,
          targetEndpoints, attackCategories, createdAt, updatedAt
        ) VALUES (
          @id, @correlationKey, @identityType, @firstSeen, @lastSeen, @status,
          @eventCount, @blockedCount, @riskScore, @riskLevel, @incidentId,
          @targetEndpoints, @attackCategories, @createdAt, @updatedAt
        )
      `);

      const insertEvent = db.prepare(`
        INSERT INTO campaign_events (id, campaignId, wafEventId, eventTimestamp, riskScoreAfterEvent)
        VALUES (@id, @campaignId, @wafEventId, @eventTimestamp, @riskScoreAfterEvent)
      `);

      const insertExpl = db.prepare(`
        INSERT INTO campaign_risk_explanations (
          campaignId, severityScore, frequencyScore, diversityScore, persistenceScore, targetScore, explanationJson, updatedAt
        ) VALUES (
          @campaignId, @severityScore, @frequencyScore, @diversityScore, @persistenceScore, @targetScore, @explanationJson, @updatedAt
        )
      `);

      const now = new Date().toISOString();
      for (const c of campaigns) {
        // Enforce 10-minute sliding window expiry for ACTIVE campaigns, preserving MITIGATED
        if (c.status === 'ACTIVE' && (Date.now() - new Date(c.lastSeen).getTime() > WINDOW_MS)) {
          c.status = 'CLOSED';
        }

        const blockedCount = c.events.filter(e => e.blocked).length;
        const endpoints = Array.from(new Set(c.events.map(e => e.uri).filter(Boolean)));
        const categories = Array.from(new Set(c.events.map(e => e.category).filter(Boolean)));

        // AUTHORITATIVE SCORING: Calculate single source-of-truth metrics and explanation
        const metrics = riskEngine.calculateContextualRisk(c.events);

        insertCamp.run({
          id: c.id,
          correlationKey: c.correlationKey,
          identityType: c.identityType,
          firstSeen: c.firstSeen,
          lastSeen: c.lastSeen,
          status: c.status,
          eventCount: c.events.length,
          blockedCount,
          riskScore: metrics.riskScore,
          riskLevel: metrics.riskLevel,
          incidentId: c.incidentId,
          targetEndpoints: JSON.stringify(endpoints),
          attackCategories: JSON.stringify(categories),
          createdAt: c.firstSeen,
          updatedAt: now
        });

        // CHRONOLOGICAL TIMELINE PROGRESSION: calculate actual risk after event i
        for (let i = 0; i < c.events.length; i++) {
          const e = c.events[i];
          const stepMetrics = riskEngine.calculateContextualRisk(c.events.slice(0, i + 1));
          insertEvent.run({
            id: `CEVT-${c.id}-${i + 1}`,
            campaignId: c.id,
            wafEventId: e.id,
            eventTimestamp: e.timestamp,
            riskScoreAfterEvent: stepMetrics.riskScore
          });
        }

        insertExpl.run({
          campaignId: c.id,
          severityScore: metrics.severityScore,
          frequencyScore: metrics.frequencyScore,
          diversityScore: metrics.diversityScore,
          persistenceScore: metrics.persistenceScore,
          targetScore: metrics.targetScore,
          explanationJson: JSON.stringify(metrics.explanation),
          updatedAt: now
        });
      }

      // Verification of invariant: every eligible event belongs to exactly one campaign
      const uniqueCorrelatedCheck = db.prepare("SELECT count(distinct wafEventId) as c FROM campaign_events").get()?.c || 0;
      if (uniqueCorrelatedCheck !== eligibleEvents.length) {
        throw new Error(`Reconciliation invariant violated: ${eligibleEvents.length} eligible events but ${uniqueCorrelatedCheck} unique linked events.`);
      }
    }

    return {
      rebuilt: needsRebuild
    };
  });

  const txRes = tx();
  const campCount = db.prepare("SELECT count(*) as c FROM attack_campaigns").get()?.c || 0;
  const evCount = db.prepare("SELECT count(*) as c FROM campaign_events").get()?.c || 0;
  const eligibleCount = db.prepare("SELECT count(*) as c FROM waf_events WHERE blocked = 1 OR (anomalyScore >= 5 AND category != 'Protocol Validation' AND category != 'Web Anomaly')").get()?.c || 0;
  const unlinkedCount = Math.max(0, eligibleCount - evCount);

  return {
    success: true,
    campaignsCount: campCount,
    linkedEventsCount: evCount,
    eligibleCount,
    unlinkedCount,
    rebuilt: txRes?.rebuilt || false
  };
}

async function reconcileMissingEligibleEvents() {
  return reconcileDatabaseCampaigns(false);
}

async function linkCampaignToIncident(campaignId, incidentId) {
  db.prepare("UPDATE attack_campaigns SET incidentId = ? WHERE id = ?").run(incidentId, campaignId);
}

module.exports = {
  getAllIncidents,
  getIncidentById,
  createIncident,
  updateIncident,
  updateIncidentStatus,
  deleteIncident,
  logAuditAction,
  resetDatabase,
  createWafEvent,
  getWafEventByTransactionId,
  getAllWafEvents,
  getWafStats,
  linkWafEventToIncident,
  // Attack Campaign Methods (Phase 2)
  getActiveCampaignByKey,
  getCampaignById,
  getAllCampaigns,
  createCampaign,
  updateCampaign,
  addCampaignEvent,
  getCampaignEvents,
  getCampaignEventByWafId,
  getCampaignByWafEventId,
  saveCampaignRiskExplanation,
  getCampaignRiskExplanation,
  getCampaignStats,
  linkCampaignToIncident,
  deriveCategory,
  isEventEligible,
  quarantineRecord,
  getQuarantineRecords,
  reconcileDatabaseCampaigns,
  reconcileMissingEligibleEvents,
  // export db for testing or complex queries later
  getDb: () => db 
};
