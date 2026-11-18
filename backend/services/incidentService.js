const db = require("./localDbService");
const crypto = require("crypto");
const { generateId } = require("../utils/idGenerator");
const { calculateSLADeadline } = require("../utils/sla");
const timelineService = require("./timelineService");

async function createIncident(body) {
  if (!body.title || !body.severity || !body.assignedTo) {
    throw new Error("title, severity, assignedTo are required");
  }

  const now = new Date().toISOString();
  const allIncidents = await db.getAllIncidents();
  const incidentId = generateId(allIncidents);
  const severity = String(body.severity).toUpperCase();

  const rawData = body.payload?.rawLog || JSON.stringify(body.payload) || "";
  const hash = rawData ? crypto.createHash("sha256").update(rawData).digest("hex") : null;

  const incident = {
    incidentId,
    title: body.title,
    description: body.description || "",
    severity,
    status: body.status || "OPEN",
    assignedTo: body.assignedTo,
    slaDeadline: body.slaDeadline || calculateSLADeadline(severity, now),
    threatType: body.threatType || body.type || "General Security Incident",
    mitreTechnique: body.mitreTechnique ? (typeof body.mitreTechnique === "string" ? body.mitreTechnique : JSON.stringify(body.mitreTechnique)) : null,
    playbook: body.playbook || null,
    payload: body.payload || null,
    rootCause: body.rootCause || null,
    extractedPayload: body.extractedPayload || null,
    confidence: body.confidence || null,
    hash,
    comments: [],
    timeline: [],
    createdAt: now,
    updatedAt: now,
    eventSource: body.eventSource || "CUSTOM_WAF",
    wafTransactionId: body.wafTransactionId || null
  };

  const createdIncident = await db.createIncident(incident);
  await timelineService.addTimelineEntry(
    createdIncident.incidentId,
    "CREATED",
    null,
    incident.status,
    createdIncident.assignedTo,
    "Incident initialized"
  );

  return db.getIncidentById(createdIncident.incidentId);
}

async function getAllIncidents(query) {
  const params = query || {};
  let incidents = await db.getAllIncidents();

  // Search keyword across ID, title, description, assignedTo
  if (params.search && params.search.trim()) {
    const q = params.search.toLowerCase().trim();
    incidents = incidents.filter(
      (inc) =>
        (inc.incidentId && inc.incidentId.toLowerCase().includes(q)) ||
        (inc.title && inc.title.toLowerCase().includes(q)) ||
        (inc.description && inc.description.toLowerCase().includes(q)) ||
        (inc.assignedTo && inc.assignedTo.toLowerCase().includes(q)) ||
        (inc.severity && inc.severity.toLowerCase().includes(q))
    );
  }

  if (params.severity) {
    incidents = incidents.filter((incident) => incident.severity === params.severity);
  }

  if (params.status) {
    incidents = incidents.filter((incident) => incident.status === params.status);
  }

  if (params.sort === "severity") {
    const weight = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4
    };
    incidents = incidents.slice().sort((a, b) => (weight[b.severity] || 0) - (weight[a.severity] || 0));
  } else if (params.sort === "sla") {
    incidents = incidents
      .slice()
      .sort((a, b) => new Date(a.slaDeadline).getTime() - new Date(b.slaDeadline).getTime());
  } else {
    // Default: newest date
    incidents = incidents
      .slice()
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  return incidents;
}

async function getIncidentById(id) {
  const incident = await db.getIncidentById(id);
  if (!incident) {
    throw new Error("Incident not found");
  }
  return incident;
}

async function updateIncident(id, body) {
  const existing = await db.getIncidentById(id);
  if (!existing) {
    throw new Error("Incident not found");
  }

  const updates = {};

  if (body.title && body.title !== existing.title) {
    updates.title = body.title;
  }
  if (body.description !== undefined && body.description !== existing.description) {
    updates.description = body.description;
  }
  if (body.severity && body.severity !== existing.severity) {
    updates.severity = body.severity;
    await timelineService.addTimelineEntry(id, "STATUS_CHANGE", existing.severity, body.severity, body.by || "System", "Severity changed");
  }

  if (body.status && body.status !== existing.status) {
    updates.status = body.status;
    if (body.status === "RESOLVED") {
      updates.resolvedAt = new Date().toISOString();
    }
    await timelineService.addTimelineEntry(id, "STATUS_CHANGE", existing.status, body.status, body.by || "System");
  }

  if (body.assignedTo && body.assignedTo !== existing.assignedTo) {
    updates.assignedTo = body.assignedTo;
    await timelineService.addTimelineEntry(id, "REASSIGNED", existing.assignedTo, body.assignedTo, body.by || "System");
  }

  if (Object.keys(updates).length > 0) {
    await db.updateIncident(id, updates);
    await db.logAuditAction("UPDATE_INCIDENT", body.by || "System", id, updates);
  }

  return db.getIncidentById(id);
}

async function addComment(id, { note, author }) {
  const existing = await db.getIncidentById(id);
  if (!existing) {
    throw new Error("Incident not found");
  }

  if (!note || !note.trim()) {
    throw new Error("Comment note cannot be empty");
  }

  const comments = Array.isArray(existing.comments) ? existing.comments : [];
  const newComment = {
    id: "CMT-" + Date.now(),
    note: note.trim(),
    author: author || "Engineer",
    timestamp: new Date().toISOString()
  };

  comments.push(newComment);
  await db.updateIncident(id, { comments });
  await timelineService.addTimelineEntry(id, "NOTE_ADDED", null, null, newComment.author, newComment.note);

  return db.getIncidentById(id);
}

async function handleQuickAction(id, { action, by, assignedTo }) {
  const existing = await db.getIncidentById(id);
  if (!existing) {
    throw new Error("Incident not found");
  }

  const actor = by || "Engineer";

  if (action === "RESOLVE") {
    await db.updateIncident(id, { status: "RESOLVED", resolvedAt: new Date().toISOString() });
    await timelineService.addTimelineEntry(id, "QUICK_RESOLVED", existing.status, "RESOLVED", actor, "Marked as resolved via quick-action");
  } else if (action === "ESCALATE") {
    let nextSeverity = "CRITICAL";
    if (existing.severity === "LOW") nextSeverity = "MEDIUM";
    else if (existing.severity === "MEDIUM") nextSeverity = "HIGH";
    else if (existing.severity === "HIGH") nextSeverity = "CRITICAL";

    await db.updateIncident(id, { severity: nextSeverity, escalated: true });
    await timelineService.addTimelineEntry(id, "ESCALATED", existing.severity, nextSeverity, actor, "Manually escalated severity");
  } else if (action === "ASSIGN_TO_ME" || action === "REASSIGN") {
    const target = assignedTo || "Current User";
    await db.updateIncident(id, { assignedTo: target });
    await timelineService.addTimelineEntry(id, "REASSIGNED", existing.assignedTo, target, actor, `Assigned to ${target}`);
  } else {
    throw new Error(`Unknown quick action: ${action}`);
  }

  await db.logAuditAction(action, actor, id, { assignedTo });

  return db.getIncidentById(id);
}

async function deleteIncident(id) {
  const incident = await db.getIncidentById(id);
  if (!incident) {
    throw new Error("Incident not found");
  }

  await db.deleteIncident(id);
  await db.logAuditAction("DELETE_INCIDENT", "System", id, null);
  return { message: "Incident deleted", id };
}

module.exports = {
  createIncident,
  getAllIncidents,
  getIncidentById,
  updateIncident,
  addComment,
  handleQuickAction,
  deleteIncident
};
