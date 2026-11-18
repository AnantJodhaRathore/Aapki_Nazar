const db = require("./localDbService");

async function addTimelineEntry(incidentId, action, from, to, by, details = "") {
  const validActions = [
    "CREATED",
    "STATUS_CHANGE",
    "REASSIGNED",
    "ESCALATED",
    "NOTE_ADDED",
    "QUICK_RESOLVED",
    "PLAYBOOK_APPLIED"
  ];

  if (!validActions.includes(action)) {
    action = "STATUS_CHANGE";
  }

  let noteStr = details;
  if (from && to) noteStr += ` [${from} -> ${to}]`;

  await db.logAuditAction(action, by || "System", incidentId, noteStr.trim());
  return true;
}

module.exports = { addTimelineEntry };
