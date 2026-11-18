/**
 * Aapki Nazar — Context-Aware Risk Scoring & Threat Prioritization Engine
 * 
 * Single authoritative implementation for:
 * 1. Endpoint asset sensitivity rating (0-100)
 * 2. Event severity and anomaly score weighting (0-100)
 * 3. 5-Factor Contextual Risk Formula:
 *    Contextual Risk = 0.35 * Severity + 0.25 * Frequency + 0.20 * Diversity + 0.10 * Persistence + 0.10 * TargetSensitivity
 * 4. Canonical CRS category derivation and eligibility predicate
 * 5. Deterministic, evidence-backed explanation and risk progression snapshots
 * 
 * Used identically by live real-time ingestion, historical backfill, and transactional reconciliation.
 */

/**
 * Deterministically maps OWASP CRS rule IDs, messages, and tags to canonical attack categories.
 */
function deriveCategory(r) {
  if (!r) return 'Web Anomaly';
  const tags = Array.isArray(r.tags) ? r.tags : (typeof r.tags === 'string' ? JSON.parse(r.tags || '[]') : []);
  const messages = Array.isArray(r.messages) ? r.messages : (typeof r.messages === 'string' ? JSON.parse(r.messages || '[]') : []);

  // 1. Inspect messages for explicit CRS rule IDs
  for (const m of messages) {
    const rid = String(m.ruleId || '');
    if (rid.startsWith('942')) return 'SQL Injection';
    if (rid.startsWith('941')) return 'Cross-Site Scripting (XSS)';
    if (rid.startsWith('932')) return 'Remote Command Execution (RCE)';
    if (rid.startsWith('930')) return 'Path Traversal / LFI';
    if (rid.startsWith('931')) return 'Remote File Inclusion (RFI)';
    if (rid.startsWith('934')) return 'Server-Side Request Forgery (SSRF)';
    if (rid.startsWith('944')) return 'Java / Log4j / Deserialization';
    if (rid.startsWith('913')) return 'Scanner / Reconnaissance';
    if (rid.startsWith('921')) return 'HTTP Protocol Attack';
  }

  // 2. Check tags
  if (tags.some(t => t.includes('attack-sqli') || t.includes('ATTACK-SQLI'))) return 'SQL Injection';
  if (tags.some(t => t.includes('attack-xss') || t.includes('ATTACK-XSS'))) return 'Cross-Site Scripting (XSS)';
  if (tags.some(t => t.includes('attack-rce') || t.includes('ATTACK-RCE'))) return 'Remote Command Execution (RCE)';
  if (tags.some(t => t.includes('attack-lfi') || t.includes('ATTACK-LFI'))) return 'Path Traversal / LFI';
  if (tags.some(t => t.includes('attack-rfi') || t.includes('ATTACK-RFI'))) return 'Remote File Inclusion (RFI)';
  if (tags.some(t => t.includes('attack-ssrf') || t.includes('ATTACK-SSRF'))) return 'Server-Side Request Forgery (SSRF)';
  if (tags.some(t => t.includes('attack-reputation-scanner') || t.includes('SCANNER-DETECTION'))) return 'Scanner / Reconnaissance';

  // 3. Fallback to primaryRuleId family code
  const match = String(r.primaryRuleId || '').match(/^(?:OWASP-CRS-)?(\d{3})/);
  if (match) {
    const p = match[1];
    if (p === '942') return 'SQL Injection';
    if (p === '941') return 'Cross-Site Scripting (XSS)';
    if (p === '932') return 'Remote Command Execution (RCE)';
    if (p === '930') return 'Path Traversal / LFI';
    if (p === '931') return 'Remote File Inclusion (RFI)';
    if (p === '934') return 'Server-Side Request Forgery (SSRF)';
    if (p === '944') return 'Java / Log4j / Deserialization';
    if (p === '913') return 'Scanner / Reconnaissance';
    if (p === '920') return 'Protocol Validation';
    if (p === '921') return 'HTTP Protocol Attack';
  }

  if (tags.some(t => t.includes('attack-protocol'))) return 'Protocol Validation';
  return 'Web Anomaly';
}

/**
 * Eligibility predicate: determines whether a WAF event is eligible to form or join an attack campaign.
 * Blocked requests (HTTP 403) or exploit anomaly scores >= 5 on active attack families are eligible.
 * Low-severity unblocked protocol warnings (Rule 920350, HTTP 200, score 0-2) are excluded.
 */
function isEventEligible(e) {
  if (!e) return false;
  if (e.blocked === true || e.blocked === 1 || e.httpCode === 403 || e.action === 'BLOCKED') return true;
  const anomaly = Number(e.anomalyScore) || 0;
  if (anomaly >= 5) {
    const cat = e.category || deriveCategory(e);
    if (cat !== 'Protocol Validation' && cat !== 'Web Anomaly') {
      return true;
    }
  }
  return false;
}

/**
 * Score an endpoint URI's sensitivity (0 - 100)
 */
function getEndpointSensitivity(uri) {
  if (!uri) return 35;
  const lower = uri.toLowerCase().split('?')[0];

  // Critical Authentication & Privilege endpoints
  if (lower.includes('/login') || lower.includes('/admin') || lower.includes('/auth') || lower.includes('/oauth') || lower.includes('/users')) {
    return 100;
  }
  // Business logic, data mutation & transaction endpoints
  if (lower.includes('/feedback') || lower.includes('/checkout') || lower.includes('/orders') || lower.includes('/pay') || lower.includes('/cart')) {
    return 75;
  }
  // Search, query & data catalog endpoints
  if (lower.includes('/products') || lower.includes('/search') || lower.includes('/catalog') || lower.includes('/items')) {
    return 60;
  }
  // Informational & static root endpoints
  if (lower === '/' || lower.includes('/index') || lower.includes('/about') || lower.includes('/contact')) {
    return 35;
  }
  // Health, metrics & diagnostic endpoints
  if (lower.includes('/health') || lower.includes('/ping') || lower.includes('/status') || lower.includes('/metrics')) {
    return 20;
  }
  return 40;
}

/**
 * Score a single event's severity contribution (0 - 100)
 */
function getEventSeverityScore(event) {
  let base = 20;
  const sev = String(event.severity || '').toUpperCase();
  if (sev === 'CRITICAL') base = 85;
  else if (sev === 'HIGH') base = 65;
  else if (sev === 'MEDIUM') base = 45;
  else base = 20;

  const anomalyScore = Number(event.anomalyScore) || 0;
  const anomalyBonus = Math.min(25, anomalyScore * 2);
  const blockedBonus = event.blocked ? 10 : 0;

  return Math.min(100, base + anomalyBonus + blockedBonus);
}

/**
 * Compute the 5 explainable factors and overall Contextual Risk Score.
 * Authoritative implementation used for live correlation, historical backfill, and reconciliation.
 */
function calculateContextualRisk(events) {
  if (!events || events.length === 0) {
    return {
      severityScore: 0,
      frequencyScore: 0,
      diversityScore: 0,
      persistenceScore: 0,
      targetScore: 0,
      riskScore: 0,
      riskLevel: 'LOW',
      explanation: {
        summary: 'No events in campaign.',
        contextualRiskScore: 0,
        riskLevel: 'LOW',
        factors: {},
        evidence: { totalEvents: 0, blockedEvents: 0, allowedEvents: 0, categories: [], endpoints: [] }
      }
    };
  }

  const eventCount = events.length;

  // 1. Severity Factor (S in [0, 100])
  const eventSevScores = events.map(e => getEventSeverityScore(e));
  const maxSev = Math.max(...eventSevScores);
  const avgSev = eventSevScores.reduce((a, b) => a + b, 0) / eventCount;
  const severityScore = Math.min(100, Math.round(0.75 * maxSev + 0.25 * avgSev));

  // 2. Frequency Factor (F in [0, 100]) - Exponential saturation curve
  const frequencyScore = Math.min(100, Math.round(100 * (1 - Math.exp(-eventCount / 3.5))));

  // 3. Diversity Factor (D in [0, 100]) - Breadth across distinct canonical attack categories
  const categoriesSet = new Set();
  events.forEach(e => {
    const cat = e.category || deriveCategory(e);
    if (cat && cat !== 'Web Anomaly' && cat !== 'Protocol Validation') {
      categoriesSet.add(cat);
    } else if (cat) {
      categoriesSet.add(cat);
    }
  });
  const distinctCategories = Array.from(categoriesSet);
  const numCats = distinctCategories.length;
  let diversityScore = 25;
  if (numCats === 1) diversityScore = 25;
  else if (numCats === 2) diversityScore = 60;
  else if (numCats === 3) diversityScore = 85;
  else diversityScore = 100;

  // 4. Persistence Factor (P in [0, 100]) - Duration & multi-moment time buckets
  const timestamps = events
    .map(e => new Date(e.timestamp || e.createdAt || Date.now()).getTime())
    .filter(t => !isNaN(t));
  let timeSpanMs = 0;
  let minuteBuckets = new Set();
  if (timestamps.length > 0) {
    const minTime = Math.min(...timestamps);
    const maxTime = Math.max(...timestamps);
    timeSpanMs = Math.max(0, maxTime - minTime);
    timestamps.forEach(t => minuteBuckets.add(Math.floor(t / 60000)));
  }

  let persistenceScore = 15;
  if (timeSpanMs < 5000) persistenceScore = 15;
  else if (timeSpanMs < 60000) persistenceScore = 40;
  else if (timeSpanMs < 180000) persistenceScore = 65;
  else if (timeSpanMs < 420000) persistenceScore = 85;
  else persistenceScore = 100;

  // Bonus if spread across multiple distinct 1-minute buckets
  if (minuteBuckets.size >= 3 && persistenceScore < 75) {
    persistenceScore = 75;
  }

  // 5. Target Sensitivity Factor (T in [0, 100])
  const endpointScores = events.map(e => getEndpointSensitivity(e.uri));
  const targetScore = Math.max(...endpointScores);

  // Composite Contextual Risk Formula:
  // Risk = 0.35 * S + 0.25 * F + 0.20 * D + 0.10 * P + 0.10 * T
  const rawScore = (0.35 * severityScore) +
                   (0.25 * frequencyScore) +
                   (0.20 * diversityScore) +
                   (0.10 * persistenceScore) +
                   (0.10 * targetScore);
  const riskScore = Math.min(100, Math.max(0, Math.round(rawScore)));

  // Risk Classification
  let riskLevel = 'LOW';
  if (riskScore >= 75) riskLevel = 'CRITICAL';
  else if (riskScore >= 50) riskLevel = 'HIGH';
  else if (riskScore >= 25) riskLevel = 'MODERATE';
  else riskLevel = 'LOW';

  // Build evidence details (truthful, non-fabricated)
  const blockedCount = events.filter(e => e.blocked).length;
  const allowedCount = eventCount - blockedCount;
  const endpointsSet = new Set(events.map(e => e.uri).filter(Boolean));
  const rulesSet = new Set(events.map(e => e.primaryRuleId).filter(Boolean));
  const maxAnomalyScore = Math.max(0, ...events.map(e => Number(e.anomalyScore) || 0));

  // Generate human-readable transparent explanation
  const timeSpanSec = Math.round(timeSpanMs / 1000);
  const timeStr = timeSpanSec >= 60 ? `${Math.floor(timeSpanSec / 60)}m ${timeSpanSec % 60}s` : `${timeSpanSec}s`;

  let summary = '';
  const blockEvidence = blockedCount > 0 ? `${blockedCount} confirmed WAF block(s)` : `${eventCount} allowed suspicious probe(s)`;
  if (riskLevel === 'CRITICAL') {
    summary = `Critical attack campaign with high multi-vector diversity (${numCats} vectors) targeting sensitive endpoints over ${timeStr} with ${blockEvidence}. Immediate defensive containment recommended.`;
  } else if (riskLevel === 'HIGH') {
    summary = `High-priority correlated threat sequence: ${eventCount} security events observed across ${timeStr} with ${blockEvidence} and multiple attack patterns.`;
  } else if (riskLevel === 'MODERATE') {
    summary = `Moderate threat activity: ${eventCount} event(s) detected with ${blockEvidence} targeting ${Array.from(endpointsSet).slice(0, 2).join(', ')}.`;
  } else {
    summary = `Low-risk threat sequence or isolated anomaly within SOC operational parameters.`;
  }

  const explanation = {
    summary,
    contextualRiskScore: riskScore,
    riskLevel,
    factors: {
      severity: {
        score: severityScore,
        weight: 0.35,
        contribution: Number((severityScore * 0.35).toFixed(1)),
        description: `Peak event severity combined with maximum CRS anomaly score (${maxAnomalyScore}) and ${blockedCount} blocked attempt(s).`
      },
      frequency: {
        score: frequencyScore,
        weight: 0.25,
        contribution: Number((frequencyScore * 0.25).toFixed(1)),
        description: `${eventCount} security event(s) recorded within active 10-minute sliding window.`
      },
      diversity: {
        score: diversityScore,
        weight: 0.20,
        contribution: Number((diversityScore * 0.20).toFixed(1)),
        description: `${numCats} distinct canonical attack category/categories observed: ${distinctCategories.slice(0, 3).join(', ')}.`
      },
      persistence: {
        score: persistenceScore,
        weight: 0.10,
        contribution: Number((persistenceScore * 0.10).toFixed(1)),
        description: `Activity sustained across ${timeStr} in ${minuteBuckets.size || 1} distinct time interval(s).`
      },
      targetSensitivity: {
        score: targetScore,
        weight: 0.10,
        contribution: Number((targetScore * 0.10).toFixed(1)),
        description: `Highest asset sensitivity rating among targeted endpoints (${Array.from(endpointsSet).slice(0, 3).join(', ')}).`
      }
    },
    evidence: {
      totalEvents: eventCount,
      blockedEvents: blockedCount,
      allowedEvents: allowedCount,
      maxAnomalyScore,
      categories: distinctCategories,
      endpoints: Array.from(endpointsSet),
      primaryRules: Array.from(rulesSet).slice(0, 5),
      timeSpanSeconds: timeSpanSec
    },
    distinctionNote: 'Upstream OWASP CRS evaluates single-request anomaly scores (threshold: 5). Aapki Nazar contextual risk correlates cross-event telemetry, velocity, vector diversity, persistence, and asset sensitivity into explainable threat prioritization.'
  };

  return {
    severityScore,
    frequencyScore,
    diversityScore,
    persistenceScore,
    targetScore,
    riskScore,
    riskLevel,
    explanation
  };
}

module.exports = {
  deriveCategory,
  isEventEligible,
  getEndpointSensitivity,
  getEventSeverityScore,
  calculateContextualRisk
};

