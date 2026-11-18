function computeHealthScore(incidents) {
  const weights = {
    LOW: 2,
    MEDIUM: 5,
    HIGH: 10,
    CRITICAL: 20
  };

  const activeIncidents = (Array.isArray(incidents) ? incidents : []).filter(
    (incident) => incident.status !== "RESOLVED"
  );

  const penalty = activeIncidents.reduce((sum, incident) => {
    return sum + (weights[incident.severity] || 0);
  }, 0);

  const score = Math.max(0, 100 - penalty);

  if (score >= 85) {
    return { score, value: penalty, label: "Optimal", color: "green" };
  }
  if (score >= 60) {
    return { score, value: penalty, label: "Elevated Risk", color: "yellow" };
  }
  if (score >= 35) {
    return { score, value: penalty, label: "At Risk", color: "orange" };
  }
  return { score, value: penalty, label: "Critical", color: "red" };
}

module.exports = { computeHealthScore };
