function generateId(existingIncidents) {
  const year = new Date().getFullYear();
  const prefix = `INC-${year}-`;
  const maxSeq = (Array.isArray(existingIncidents) ? existingIncidents : [])
    .filter(i => i.incidentId && i.incidentId.startsWith(prefix))
    .map(i => parseInt(i.incidentId.slice(prefix.length), 10))
    .filter(n => !isNaN(n))
    .reduce((max, n) => Math.max(max, n), 0);
  const sequence = String(maxSeq + 1).padStart(4, "0");
  return `${prefix}${sequence}`;
}

module.exports = { generateId };
