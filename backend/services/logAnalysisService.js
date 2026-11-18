const path = require("path");
const fs = require("fs");

const RULES_FILE = path.join(__dirname, "../config/detection_rules.json");

const { SEVERITY_WEIGHTS, THRESHOLDS, RISK_SCORING } = require("../config/constants");

// MITRE ATT&CK Technique Mapping
const MITRE_MAPPING = {
  "SQL Injection": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "NoSQL Injection": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "XSS": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "Path Traversal": { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
  "Local File Inclusion": { id: "T1005", name: "Data from Local System", tactic: "Collection" },
  "Command Injection": { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  "SSRF": { id: "T1090", name: "Proxy: Internal Redirection", tactic: "Command and Control" },
  "XXE": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "Brute Force": { id: "T1110", name: "Brute Force: Credential Stuffing", tactic: "Credential Access" },
  "Data Exfiltration": { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  "Sensitive Data Exposure": { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },
  "PII Exposure": { id: "T1005", name: "Data from Local System", tactic: "Collection" },
  "Scanner Detection": { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
  "LDAP Injection": { id: "T1087.002", name: "Domain Account Discovery", tactic: "Discovery" },
  "Insecure Deserialization": { id: "T1203", name: "Exploitation for Client Execution", tactic: "Execution" },
  "HTTP Header Injection": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "Configuration Exposure": { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  "Server-Side Template Injection": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "Log4Shell": { id: "T1190", name: "Exploit Public-Facing Application: Log4j", tactic: "Initial Access" },
  "Open Redirect": { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access" },
  "GraphQL Introspection": { id: "T1595.002", name: "Vulnerability Scanning", tactic: "Reconnaissance" },
  "CRLF Injection": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "JWT Exposure": { id: "T1552.001", name: "Credentials in Files", tactic: "Credential Access" },
  "Information Disclosure": { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  "Velocity Anomaly / DDoS": { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
  "High Entropy Obfuscation": { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" }
};

// Safe URL Decoder Helper (Bounded Multi-pass)
function safeUrlDecode(str, depth = 0) {
  if (!str || typeof str !== "string" || depth > 2) return str;
  try {
    const decoded = decodeURIComponent(str.replace(/\+/g, " "));
    if (decoded === str) return decoded;
    return safeUrlDecode(decoded, depth + 1);
  } catch {
    return str;
  }
}

// Simulated Geo-Location Lookup
const GEO_REGIONS = [
  { prefix: "198.51.100", country: "Russia", city: "St. Petersburg", code: "RU" },
  { prefix: "45.33", country: "USA", city: "New York", code: "US" },
  { prefix: "103.251", country: "China", city: "Beijing", code: "CN" },
  { prefix: "185", country: "Brazil", city: "São Paulo", code: "BR" },
  { prefix: "194.26", country: "Iran", city: "Tehran", code: "IR" },
  { prefix: "203.0.113", country: "North Korea", city: "Pyongyang", code: "KP" }
];

function getSimulatedGeo(ip) {
  if (!ip || ip === "unknown" || ip.startsWith("10.") || ip.startsWith("172.") || ip.startsWith("192.") || ip === "127.0.0.1") {
    return { country: "Internal Network", city: "Datacenter", code: "LOCAL" };
  }
  for (const region of GEO_REGIONS) {
    if (ip.startsWith(region.prefix)) return region;
  }
  return { country: "Unknown Origin", city: "Unknown", code: "UN" };
}

// In-Memory Allowlist (Zero False Positive Tuning)
const ALLOWLIST = {
  ips: new Set(["127.0.0.1", "::1", "10.0.0.254", "internal-scanner.corp.local"]),
  safePaths: [/^\/api\/health$/, /^\/favicon\.ico$/, /^\/assets\//, /^\/robots\.txt$/]
};

// In-Memory IP Velocity Tracking Cache (Sliding Window: 10s)
const ipVelocityCache = new Map();

// Detection Latency Tracking
const latencySamples = [];
function recordDetectionLatency(ms) {
  latencySamples.push(ms);
  if (latencySamples.length > 100) latencySamples.shift();
}
function getAverageDetectionLatency() {
  if (latencySamples.length === 0) return 0;
  const sum = latencySamples.reduce((a, b) => a + b, 0);
  return parseFloat((sum / latencySamples.length).toFixed(3));
}

function trackVelocity(ip) {
  if (!ip || ip === "unknown") return { count: 1, isAnomaly: false };
  const now = Date.now();
  const windowMs = THRESHOLDS.VELOCITY_WINDOW_MS;
  const threshold = THRESHOLDS.VELOCITY_MAX_REQS;

  let timestamps = ipVelocityCache.get(ip) || [];
  timestamps = timestamps.filter(t => now - t < windowMs);
  timestamps.push(now);
  ipVelocityCache.set(ip, timestamps);

  if (ipVelocityCache.size > 2000) {
    for (const [k, v] of ipVelocityCache.entries()) {
      if (v.length === 0 || now - v[v.length - 1] > windowMs) {
        ipVelocityCache.delete(k);
      }
    }
  }

  return {
    count: timestamps.length,
    isAnomaly: timestamps.length >= threshold,
    ratePerSec: (timestamps.length / (windowMs / 1000)).toFixed(1)
  };
}

// Stage 1: Universal Log Normalizer (Format Agnostic)
function normalizeLog(raw) {
  if (!raw || typeof raw !== "string") {
    return { format: "empty", sourceIp: "unknown", method: "GET", path: "/", payload: "", raw: "" };
  }

  const trimmed = raw.trim();

  // 1. Try JSON (AWS CloudTrail, Envoy, Kubernetes, WAF logs)
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const parsed = JSON.parse(trimmed);
      return {
        format: "JSON (Cloud/WAF)",
        sourceIp: parsed.sourceIPAddress || parsed.src_ip || parsed.client_ip || parsed.ip || parsed.source_ip || "unknown",
        method: (parsed.requestMethod || parsed.method || parsed.http_method || "GET").toUpperCase(),
        path: parsed.requestURI || parsed.uri || parsed.path || parsed.url || "/",
        statusCode: parsed.responseCode || parsed.status || parsed.statusCode || 200,
        userAgent: parsed.userAgent || parsed.user_agent || "unknown",
        payload: JSON.stringify(parsed.requestParameters || parsed.body || parsed.payload || parsed),
        raw: trimmed
      };
    } catch {}
  }

  // 1.5. Try AWS CloudTrail CSV
  // Example: 3038ebd2-c98a...,2017-02,255.253,console.amazonaws.com,GetAccountPasswordPolicy,iam.amazonaws.com,...
  const csvParts = trimmed.split(',');
  if (csvParts.length >= 15 && csvParts[0].match(/^[0-9a-f]{8}-[0-9a-f]{4}/i)) {
    return {
      format: "AWS CloudTrail (CSV)",
      sourceIp: csvParts[2] && csvParts[2] !== "Unknown" ? csvParts[2] : "unknown",
      method: "AWS_API",
      path: csvParts[5] + " / " + csvParts[4],
      statusCode: (csvParts[15] === "None" || csvParts[15] === "NoError") ? 200 : 403,
      userAgent: csvParts[3],
      payload: trimmed,
      raw: trimmed
    };
  }

  // 2. Try Common Log Format (CLF) / Nginx / Apache
  // Example: 192.168.1.50 - - [19/Aug/2026:12:00:00 +0000] "POST /api/login HTTP/1.1" 200 4523 - payload: {"user":"admin"}
  const clfMatch = trimmed.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s?#]+)(?:\?([^\s#]*))?\s+[^"]*"\s+(\d{3})\s+(\d+|-)(?:\s+(.*))?$/s);
  if (clfMatch) {
    const trailing = clfMatch[8] || "";
    return {
      format: "Common Log Format (Nginx/Apache)",
      sourceIp: clfMatch[1],
      timestamp: clfMatch[2],
      method: clfMatch[3].toUpperCase(),
      path: clfMatch[4],
      queryParams: clfMatch[5] || "",
      statusCode: parseInt(clfMatch[6], 10),
      payload: (clfMatch[4] + (clfMatch[5] ? "?" + clfMatch[5] : "") + " " + trailing).trim(),
      raw: trimmed
    };
  }

  // 3. Try Syslog RFC 3164 / 5424
  const syslogMatch = trimmed.match(/^<(\d+)>(?:1\s+)?(\S+)\s+(\S+)\s+([^\s:]+)(?::|\s)\s*(.*)$/s);
  if (syslogMatch) {
    const message = syslogMatch[5] || "";
    const ipMatch = message.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    return {
      format: "Syslog (Firewall/OS)",
      sourceIp: ipMatch ? ipMatch[0] : syslogMatch[3],
      process: syslogMatch[4],
      payload: message,
      raw: trimmed
    };
  }

  // 4. Heuristic Extraction (Fallback)
  const ipExtract = trimmed.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  const methodExtract = trimmed.match(/\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b/i);
  const pathExtract = trimmed.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s?#\n]+)/i);

  return {
    format: "Heuristic (Unstructured String)",
    sourceIp: ipExtract ? ipExtract[0] : "unknown",
    method: methodExtract ? methodExtract[1].toUpperCase() : "GET",
    path: pathExtract ? pathExtract[1] : "/",
    payload: trimmed,
    raw: trimmed
  };
}

// Stage 4: Shannon Entropy Analysis
function calculateEntropy(str) {
  if (!str || typeof str !== "string" || str.length < 10) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

let detectionRules = [];

function loadRules() {
  try {
    if (fs.existsSync(RULES_FILE)) {
      const raw = fs.readFileSync(RULES_FILE, "utf-8");
      detectionRules = JSON.parse(raw);
    }
  } catch (err) {
    console.error("Failed to load detection rules:", err);
    detectionRules = [];
  }
}

loadRules();

function generatePlaybook(threatType, topRule, matches, sourceIp, mitre) {
  const matchedRuleNames = matches.map(m => m.id).join(", ");
  const ip = sourceIp && sourceIp !== "unknown" ? sourceIp : "attacker_ip";

  switch (threatType) {
    case "SQL Injection":
      return {
        summary: `Detected SQL injection attempt matching rules: ${matchedRuleNames}. Attacker attempting dynamic SQL injection via query parameters.`,
        rootCause: "Unescaped string interpolation into database query parameters.",
        immediateAction: `Add IP [${ip}] to AWS WAF / Cloudflare blocklist. Inspect ORM query builder.`,
        codeRemediation: "Replace dynamic SQL queries with parameterized queries or prepared statements:\n// Example:\n// Before: db.query(`SELECT * FROM users WHERE id = '${userId}'`)\n// After:  db.query('SELECT * FROM users WHERE id = ?', [userId])",
        containmentCommand: `iptables -A INPUT -s ${ip} -j DROP # Instant IP Containment`,
        mitreInfo: mitre || { id: "T1190", name: "Exploit Public-Facing Application" }
      };
    case "XSS":
      return {
        summary: `Cross-Site Scripting (XSS) payload identified (${matchedRuleNames}). Malicious script execution attempted in victim browsers.`,
        rootCause: "Unsanitized user-supplied HTML/JS rendered directly into browser DOM.",
        immediateAction: `Enforce Content Security Policy (CSP): "default-src 'self'; script-src 'self'". Block source ${ip}.`,
        codeRemediation: "Escape HTML entities before rendering or use DOMPurify:\nimport DOMPurify from 'dompurify';\nconst cleanHTML = DOMPurify.sanitize(dirtyInput);",
        containmentCommand: `curl -X POST https://waf.local/api/block -d '{"ip":"${ip}","reason":"XSS"}'`,
        mitreInfo: mitre || { id: "T1059.007", name: "JavaScript Execution" }
      };
    case "Path Traversal":
    case "Local File Inclusion":
      return {
        summary: `Directory traversal attack detected (${matchedRuleNames}). Attempting to access sensitive system files outside the web root.`,
        rootCause: "User-controlled file path parameter passed to filesystem functions without canonical path verification.",
        immediateAction: "Block requests containing `../` or `%2e%2e%2f` at the reverse proxy / API gateway level.",
        codeRemediation: "const safePath = path.resolve(BASE_DIR, path.basename(userFileName));\nif (!safePath.startsWith(BASE_DIR)) throw new Error('Access denied');",
        containmentCommand: `iptables -A INPUT -s ${ip} -j DROP`,
        mitreInfo: mitre || { id: "T1083", name: "File and Directory Discovery" }
      };
    case "Velocity Anomaly / DDoS":
    case "Brute Force":
      return {
        summary: `Authentication failure / Brute force probe detected from source [${ip}].`,
        rootCause: "Automated credential stuffing or denial of service script targeting endpoint.",
        immediateAction: `Enable IP rate-limiting middleware (express-rate-limit) and challenge source [${ip}] with CAPTCHA or temporary 1-hour ban.`,
        codeRemediation: "app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));",
        containmentCommand: `fail2ban-client set nginx-limit-req banip ${ip}`,
        mitreInfo: mitre || { id: "T1110", name: "Brute Force" }
      };
    default:
      return {
        summary: `Suspicious activity detected matching rule ${topRule?.id || 'ANOMALY_001'} from IP ${ip}.`,
        rootCause: "Anomalous request payload triggered security pattern detection.",
        immediateAction: `Inspect recent traffic logs from source [${ip}] and monitor for repeated pattern violations.`,
        codeRemediation: "Enforce strict schema validation (e.g. Zod or Joi) on all inbound API parameters.",
        containmentCommand: `iptables -A INPUT -s ${ip} -j DROP`,
        mitreInfo: mitre || { id: "T1190", name: "Exploit Public-Facing Application" }
      };
  }
}

function extractPayload(logs, matches) {
  for (const match of matches) {
    if (match.pattern) {
      try {
        const cleanedPattern = match.pattern.replace(/^\(\?i\)/, "");
        const regex = new RegExp(cleanedPattern, "gi");
        const found = logs.match(regex);
        if (found && found[0]) {
          return found[0];
        }
      } catch {}
    }
  }
  return null;
}

// 5-STAGE HYBRID DETECTION ENGINE
function detectThreat(rawLogs) {
  const startNs = process.hrtime.bigint();

  if (!Array.isArray(detectionRules) || detectionRules.length === 0) {
    loadRules();
  }

  // ── STAGE 1: Universal Normalization & URL Decoding ──
  const normalized = normalizeLog(rawLogs);
  normalized.geo = getSimulatedGeo(normalized.sourceIp);
  const decodedRaw = safeUrlDecode(rawLogs);
  const decodedPayload = safeUrlDecode(normalized.payload || "");
  
  // Create search spaces (both raw and decoded)
  const searchSpace = `${rawLogs} ${decodedRaw} ${normalized.path} ${normalized.queryParams || ''} ${normalized.payload || ''} ${decodedPayload}`;

  // ── FALSE POSITIVE / ALLOWLIST CHECK ──
  if (ALLOWLIST.ips.has(normalized.sourceIp)) {
    const endNs = process.hrtime.bigint();
    recordDetectionLatency(Number(endNs - startNs) / 1e6);
    return {
      status: "clean",
      type: "none",
      severity: "LOW",
      threatScore: 0,
      riskLevel: "Allowlisted Internal IP",
      normalizedLog: normalized,
      matchedRules: [],
      extractedPayload: null,
      entropy: calculateEntropy(normalized.payload),
      playbook: null
    };
  }

  if (ALLOWLIST.safePaths.some(rgx => rgx.test(normalized.path))) {
    const endNs = process.hrtime.bigint();
    recordDetectionLatency(Number(endNs - startNs) / 1e6);
    return {
      status: "clean",
      type: "none",
      severity: "LOW",
      threatScore: 0,
      riskLevel: "Allowlisted Safe Path",
      normalizedLog: normalized,
      matchedRules: [],
      extractedPayload: null,
      entropy: calculateEntropy(normalized.payload),
      playbook: null
    };
  }

  // ── STAGE 2: Signature Engine (Regex) ──
  const matches = [];
  for (const rule of detectionRules) {
    const pattern = rule.pattern;
    if (!pattern) continue;

    let count = 0;
    if (rule.regex) {
      try {
        const cleanedPattern = pattern.replace(/^\(\?i\)/, "");
        const regex = new RegExp(cleanedPattern, "gi");
        const found = searchSpace.match(regex);
        count = found ? found.length : 0;
      } catch {
        continue;
      }
    } else {
      const lowerPattern = pattern.toLowerCase();
      if (searchSpace.toLowerCase().includes(lowerPattern)) {
        count = searchSpace.toLowerCase().split(lowerPattern).length - 1;
      }
    }

    if (count <= 0) continue;
    if (rule.repeatThreshold && count < rule.repeatThreshold) continue;

    matches.push({
      id: rule.id,
      type: rule.type,
      severity: rule.severity || "LOW",
      priority: rule.priority || 50,
      description: rule.description || "",
      pattern: pattern,
      count: count
    });
  }

  // ── STAGE 3: Velocity & Behavioral Tracking ──
  const velocity = trackVelocity(normalized.sourceIp);
  if (velocity.isAnomaly) {
    matches.push({
      id: "VELOCITY_ANOMALY",
      type: "Velocity Anomaly / DDoS",
      severity: "HIGH",
      description: `High request velocity detected (${velocity.count} requests / 10s from IP ${normalized.sourceIp}).`,
      count: velocity.count
    });
  }

  // ── STAGE 4: Shannon Entropy Analysis ──
  // Extract long strings or base64 segments to calculate localized entropy
  // We prioritize the payload over the entire raw log to avoid false positives on long normal headers
  const entropyTarget = normalized.payload && normalized.payload.length > 20 ? normalized.payload : rawLogs;
  const entropy = calculateEntropy(entropyTarget);
  const hasBase64OrEval = /base64_decode|eval\(|fromCharCode|powershell.*-e/i.test(searchSpace);
  const isHighEntropy = (entropy > THRESHOLDS.ENTROPY_MIN_BITS && entropyTarget.length > THRESHOLDS.ENTROPY_MIN_LEN);

  if (isHighEntropy && !matches.some(m => m.severity === "CRITICAL")) {
    matches.push({
      id: "HIGH_ENTROPY_001",
      type: "High Entropy Indicator",
      severity: "MEDIUM",
      description: `Payload contains high Shannon entropy (${entropy}) indicating potential obfuscation or packed code.`,
      count: 1
    });
  }
  
  if (hasBase64OrEval) {
    matches.push({
      id: "OBFUSCATION_001",
      type: "Encoded Execution Indicator",
      severity: "HIGH",
      description: `Payload contains clear indicators of encoded execution (eval, base64_decode).`,
      count: 1
    });
  }

  // ── STAGE 5: Composite Threat Risk Scoring (0 - 100) ──
  if (matches.length === 0) {
    const endNs = process.hrtime.bigint();
    recordDetectionLatency(Number(endNs - startNs) / 1e6);
    return {
      status: "clean",
      type: "none",
      severity: "LOW",
      threatScore: 0,
      riskLevel: "Verified Clean Traffic",
      normalizedLog: normalized,
      matchedRules: [],
      extractedPayload: null,
      entropy,
      velocity,
      playbook: null
    };
  }

  // Calculate composite score using priority for collision resolution
  const highest = matches.reduce((max, item) => {
    const itemPriority = item.priority || SEVERITY_WEIGHTS[item.severity] * 10 || 10;
    const maxPriority = max.priority || SEVERITY_WEIGHTS[max.severity] * 10 || 10;
    return itemPriority > maxPriority ? item : max;
  }, matches[0]);

  let baseScore = RISK_SCORING.BASE[highest.severity] || RISK_SCORING.BASE.LOW;

  let compositeScore = baseScore;
  if (matches.length > 1) compositeScore += (matches.length - 1) * RISK_SCORING.BONUS_MULTIPLE;
  if (isHighEntropy) compositeScore += RISK_SCORING.ENTROPY_BONUS;
  if (velocity.isAnomaly) compositeScore += RISK_SCORING.VELOCITY_BONUS;
  compositeScore = Math.min(100, compositeScore);

  const extractedPayload = extractPayload(searchSpace, matches);
  const mitre = MITRE_MAPPING[highest.type] || { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" };
  const playbook = generatePlaybook(highest.type, highest, matches, normalized.sourceIp, mitre);

  // Forensic Evidence Package
  const forensicPackage = {
    incidentId: `EVD-${Date.now().toString(36).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    sourceIp: normalized.sourceIp,
    geo: normalized.geo,
    logFormat: normalized.format,
    threatType: highest.type,
    threatScore: compositeScore,
    severity: highest.severity,
    entropy: `${entropy} bits/char`,
    velocity: `${velocity.count} reqs in 10s`,
    mitreTechnique: `${mitre.id} (${mitre.name})`,
    extractedPayload: extractedPayload || normalized.payload,
    rawLog: rawLogs
  };

  const endNs = process.hrtime.bigint();
  recordDetectionLatency(Number(endNs - startNs) / 1e6);

  return {
    status: "threat_detected",
    type: highest.type,
    severity: highest.severity,
    threatScore: compositeScore,
    riskLevel: compositeScore >= 80 ? "HIGH" : compositeScore >= 50 ? "MEDIUM" : "LOW",
    scoreBreakdown: {
      baseScore,
      signatureBonus: (matches.length > 1) ? (matches.length - 1) * RISK_SCORING.BONUS_MULTIPLE : 0,
      entropyBonus: isHighEntropy ? RISK_SCORING.ENTROPY_BONUS : 0,
      velocityBonus: velocity.isAnomaly ? RISK_SCORING.VELOCITY_BONUS : 0
    },
    normalizedLog: normalized,
    matchedRules: matches,
    topRuleId: highest.id,
    mitre,
    entropy,
    velocity,
    extractedPayload,
    playbook,
    forensicPackage
  };
}

async function analyzeLogs(logs) {
  if (!logs || !logs.trim()) {
    throw new Error("Logs cannot be empty");
  }
  return detectThreat(logs);
}

module.exports = {
  analyzeLogs,
  detectThreat,
  generatePlaybook,
  normalizeLog,
  calculateEntropy,
  safeUrlDecode,
  MITRE_MAPPING,
  getAverageDetectionLatency
};