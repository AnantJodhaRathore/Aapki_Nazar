const { SLA_DURATIONS } = require("../config/constants");

function calculateSLADeadline(severity, createdAt) {
  const normalizedSeverity = String(severity || "LOW").toUpperCase();
  const baseDate = new Date(createdAt);
  const hoursToAdd = SLA_DURATIONS[normalizedSeverity] ?? SLA_DURATIONS.LOW;
  const deadline = new Date(baseDate.getTime() + hoursToAdd * 60 * 60 * 1000);
  return deadline.toISOString();
}

module.exports = { calculateSLADeadline };
