const Database = require('better-sqlite3');
const path = require('path');

const DB_FILE = path.join(__dirname, '../database.sqlite');
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

  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      targetId TEXT,
      details TEXT,
      timestamp TEXT NOT NULL
    );
  `);

}

function resetDatabase() {
  const resetTx = db.transaction(() => {
    db.prepare("DELETE FROM incidents").run();
    db.prepare("DELETE FROM audit_logs").run();
  });

  resetTx();
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
    resolvedAt: row.resolvedAt
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
    INSERT INTO incidents (incidentId, title, description, severity, status, assignedTo, slaDeadline, escalated, timeline, playbook, payload, comments, rootCause, extractedPayload, confidence, threatType, mitreTechnique, hash, createdAt, updatedAt, resolvedAt)
    VALUES (@incidentId, @title, @description, @severity, @status, @assignedTo, @slaDeadline, @escalated, @timeline, @playbook, @payload, @comments, @rootCause, @extractedPayload, @confidence, @threatType, @mitreTechnique, @hash, @createdAt, @updatedAt, @resolvedAt)
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
    resolvedAt: data.resolvedAt || null
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
      resolvedAt = @resolvedAt
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

module.exports = {
  getAllIncidents,
  getIncidentById,
  createIncident,
  updateIncident,
  updateIncidentStatus,
  deleteIncident,
  logAuditAction,
  resetDatabase,
  // export db for testing or complex queries later
  getDb: () => db 
};
