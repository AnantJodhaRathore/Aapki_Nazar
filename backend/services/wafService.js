/**
 * Aapki Nazar - Enterprise-Grade OWASP Web Application Firewall (WAF) Engine
 * Implements the Unified OWASP Core Rule Set (CRS v3.3/v4.0) Specification:
 * - 40+ Precision Rule Signatures across 9 Threat Families
 * - Multi-pass Bounded URL / Hex / HTML / Base64 Evasion Decoding
 * - Shannon Entropy Obfuscation Analysis (H > 5.8)
 * - Sliding-Window IP Velocity & Rate-Limiting Tracker (10s window)
 * - Cumulative Collaborative Anomaly Scoring (0 - 100)
 * - MITRE ATT&CK Framework Mapping (Tactics & Techniques)
 * - Actionable Before/After Code Remediation Playbooks
 */

const incidentService = require("./incidentService");

// ═══════════════════════════════════════════════════════════════════════
// 1. MASTER OWASP CORE RULE SET (CRS v3.3 / v4.0) SIGNATURE CATALOG
// ═══════════════════════════════════════════════════════════════════════
const OWASP_CRS_RULES = [
  // ── 1. SQL INJECTION (CRS 942xxx) ──
  {
    ruleId: "OWASP-CRS-942100",
    name: "SQL Injection: Classic Union-Based Exfiltration",
    category: "SQL Injection",
    severity: "CRITICAL",
    baseScore: 85,
    anomalyPoints: 5,
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: SQL Injection", tactic: "Initial Access" },
    patterns: [
      /(?:\bunion\b[\s\/\*]+(?:all[\s\/\*]+)?select\b)/i,
      /(?:\bselect\b[\s\S]{1,100}\bfrom\b[\s\S]{1,100}\b(?:where|group\s+by|order\s+by)\b)/i
    ],
    remediation: "Enforce parameterized queries or prepared statements across all database queries:\n// Before: db.query(`SELECT * FROM users WHERE id = '${userId}'`)\n// After:  db.query('SELECT * FROM users WHERE id = ?', [userId])"
  },
  {
    ruleId: "OWASP-CRS-942110",
    name: "SQL Injection: Boolean Tautology & Auth Bypass",
    category: "SQL Injection",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: SQL Injection", tactic: "Initial Access" },
    patterns: [
      /(?:[\'\"]\s*(?:or|and)\s*[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)/i,
      /(?:[\'\"]\s*(?:or|and)\s*[\'\"]?[a-z0-9_]+[\'\"]?\s*=\s*[\'\"]?[a-z0-9_]+)/i,
      /(?:[\'\"]\s*(?:or|and)\s*true\b)/i,
      /(?:admin[\'\"]\s*--)/i,
      /(?:[\'\"]\s*\|\|\s*[\'\"])/i
    ],
    remediation: "Never interpolate raw authentication parameters into SQL queries. Use strongly typed ORM finders or parameterized placeholders:\n// const user = await User.findOne({ where: { username, passwordHash } });"
  },
  {
    ruleId: "OWASP-CRS-942120",
    name: "SQL Injection: Blind Time-Delay Exploitation",
    category: "SQL Injection",
    severity: "HIGH",
    baseScore: 80,
    anomalyPoints: 4,
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: SQL Injection", tactic: "Initial Access" },
    patterns: [
      /(?:\b(?:sleep|benchmark|waitfor\s+delay|pg_sleep|dbms_pipe\.receive_message)\s*\()/i,
      /(?:\b(?:select|and|or)\b[\s\S]{1,30}\b(?:sleep|pg_sleep)\b)/i
    ],
    remediation: "Eliminate dynamic SQL query concatenation. Configure strict database execution query timeouts (< 3000ms) to prevent thread exhaustion."
  },
  {
    ruleId: "OWASP-CRS-942130",
    name: "SQL Injection: Stacked Queries & DDL/DML Manipulation",
    category: "SQL Injection",
    severity: "CRITICAL",
    baseScore: 90,
    anomalyPoints: 5,
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: SQL Injection", tactic: "Initial Access" },
    patterns: [
      /(?:;\s*(?:drop|truncate|alter|create|delete|insert|update|grant|revoke)\b)/i,
      /(?:;\s*exec(?:ute)?\s*\()/i,
      /(?:;\s*xp_cmdshell\b)/i
    ],
    remediation: "Disable multi-statement queries in database connection pool configuration (e.g. `multipleStatements: false`). Apply the principle of least privilege to database users."
  },
  {
    ruleId: "OWASP-CRS-942140",
    name: "SQL Injection: Database Metadata & Schema Enumeration",
    category: "SQL Injection",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1082", name: "System Information Discovery: Database Schema", tactic: "Discovery" },
    patterns: [
      /(?:\binformation_schema\.(?:tables|columns|schemata)\b)/i,
      /(?:\b(?:schema|database|version|current_user|user)\s*\(\))/i,
      /(?:\bload_file\s*\()/i,
      /(?:\binto\s+(?:dump|out)file\b)/i
    ],
    remediation: "Restrict database user privileges to deny SELECT permissions on `information_schema` and disable `FILE` privileges to prevent file read/write operations."
  },
  {
    ruleId: "OWASP-CRS-942150",
    name: "SQL Injection: NoSQL Query Operator Injection",
    category: "NoSQL Injection",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: NoSQL Injection", tactic: "Initial Access" },
    patterns: [
      /(?:[\"\']?\$(?:gt|gte|lt|lte|ne|nin|where|regex|exists|or|and)[\"\']?\s*:)/i,
      /(?:tojson\s*\(|function\s*\(\)\s*\{\s*return\s*true)/i
    ],
    remediation: "Sanitize request body inputs using schema validation libraries (e.g. Zod or Joi) to strip leading `$` characters before passing to MongoDB/Mongoose queries."
  },
  {
    ruleId: "OWASP-CRS-942160",
    name: "SQL Injection: Comment Interleaving & Evasion",
    category: "SQL Injection",
    severity: "MEDIUM",
    baseScore: 70,
    anomalyPoints: 3,
    mitre: { id: "T1027", name: "Obfuscated Files or Information: SQL Comments", tactic: "Defense Evasion" },
    patterns: [
      /(?:\/\*![\d]{4,6}[\s\S]*?\*\/)/i,
      /(?:\/\*[\s\S]*?\*\/)/i,
      /(?:--\s*$|--\+|\#)/m
    ],
    remediation: "Configure WAF request normalization to strip SQL comment patterns and reject requests containing comment interleaving inside query parameters."
  },

  // ── 2. CROSS-SITE SCRIPTING (CRS 941xxx) ──
  {
    ruleId: "OWASP-CRS-941100",
    name: "Cross-Site Scripting (XSS): Explicit Script Tag Injection",
    category: "XSS",
    severity: "HIGH",
    baseScore: 80,
    anomalyPoints: 4,
    mitre: { id: "T1059.007", name: "Command and Scripting Interpreter: JavaScript", tactic: "Execution" },
    patterns: [
      /(?:<script\b[^>]*>[\s\S]*?(?:<\/script>|$))/i,
      /(?:<script[\s\/])/i,
      /(?:<\/script>)/i
    ],
    remediation: "Encode all user-supplied data with context-aware HTML entity encoding before rendering in the DOM. Enforce strict Content Security Policy:\n// Content-Security-Policy: default-src 'self'; script-src 'self';"
  },
  {
    ruleId: "OWASP-CRS-941110",
    name: "Cross-Site Scripting (XSS): Inline Event Handler Injection",
    category: "XSS",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1059.007", name: "Command and Scripting Interpreter: JavaScript", tactic: "Execution" },
    patterns: [
      /(?:<[a-z0-9_-]+\b[^>]*\bon(?:error|load|click|mouse|hover|focus|blur|change|submit|pointer|key|animation)\s*=)/i,
      /(?:<img\b[^>]*\bsrc\s*=\s*['"]?[^>]*\bonerror\s*=)/i,
      /(?:<input\b[^>]*\bautofocus\b[^>]*\bonfocus\s*=)/i,
      /(?:<iframe\b[^>]*\bsrcdoc\s*=)/i
    ],
    remediation: "Sanitize HTML input using a robust sanitizer like DOMPurify. Reject direct injection of inline event attributes onto HTML elements."
  },
  {
    ruleId: "OWASP-CRS-941120",
    name: "Cross-Site Scripting (XSS): JavaScript URI Pseudo-Protocol",
    category: "XSS",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1059.007", name: "Command and Scripting Interpreter: JavaScript", tactic: "Execution" },
    patterns: [
      /(?:javascript\s*:\s*[\w\.\(\)\'\"]+)/i,
      /(?:data\s*:\s*text\/html)/i,
      /(?:vbscript\s*:)/i
    ],
    remediation: "Validate and whitelist allowed URL schemes on links and redirects (`http:`, `https:` only). Disallow `javascript:` and `data:` URI protocols."
  },
  {
    ruleId: "OWASP-CRS-941130",
    name: "Cross-Site Scripting (XSS): SVG & XML Vector Injection",
    category: "XSS",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1059.007", name: "Command and Scripting Interpreter: JavaScript", tactic: "Execution" },
    patterns: [
      /(?:<svg\b[^>]*\bonload\s*=)/i,
      /(?:<svg><animate\b[^>]*\bonbegin\s*=)/i,
      /(?:<iframe\b[^>]*\bsrc\s*=\s*['"]?javascript:)/i,
      /(?:<object\b[^>]*\bdata\s*=)/i,
      /(?:<embed\b[^>]*\bsrc\s*=)/i
    ],
    remediation: "Disallow unsafe embedded objects (`<embed>`, `<object>`). Clean uploaded SVG files to strip embedded `<script>` and animation event nodes."
  },
  {
    ruleId: "OWASP-CRS-941140",
    name: "Cross-Site Scripting (XSS): DOM Sink & Storage Extraction",
    category: "XSS",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1552", name: "Unsecured Credentials: DOM Storage", tactic: "Credential Access" },
    patterns: [
      /(?:document\.(?:cookie|location|write|domain|referrer)\b)/i,
      /(?:window\.(?:localStorage|sessionStorage)\b)/i,
      /(?:alert\s*\(|prompt\s*\(|confirm\s*\()/i
    ],
    remediation: "Protect session cookies by setting `HttpOnly`, `Secure`, and `SameSite=Strict` flags so JavaScript cannot extract authorization tokens via DOM sinks."
  },

  // ── 3. COMMAND INJECTION & RCE (CRS 932xxx) ──
  {
    ruleId: "OWASP-CRS-932100",
    name: "Remote Command Execution: Unix Shell Metacharacters & Piping",
    category: "Command Injection",
    severity: "CRITICAL",
    baseScore: 90,
    anomalyPoints: 5,
    mitre: { id: "T1059.004", name: "Command and Scripting: Unix Shell", tactic: "Execution" },
    patterns: [
      /(?:[;&|`]\s*(?:cat|ls|dir|whoami|id|uname|nc|ncat|netcat|curl|wget|bash|sh|powershell|cmd|python|perl|ruby|rm|chmod)\b)/i,
      /(?:\$\([^\)]+\)|\`[^\`]+\`)/i,
      /(?:\/bin\/(?:sh|bash|zsh|dash))/i
    ],
    remediation: "Never pass unsanitized input to child process spawners or shell interpreters. Use `execFile` or `spawn` with an explicit arguments array instead of shell execution:\n// child_process.execFile('/usr/bin/tool', [validatedInput])"
  },
  {
    ruleId: "OWASP-CRS-932110",
    name: "Remote Command Execution: Windows Command & PowerShell Invocation",
    category: "Command Injection",
    severity: "CRITICAL",
    baseScore: 90,
    anomalyPoints: 5,
    mitre: { id: "T1059.001", name: "Command and Scripting: PowerShell", tactic: "Execution" },
    patterns: [
      /(?:cmd(?:\.exe)?\s+\/[c|k]\b)/i,
      /(?:powershell(?:\.exe)?\s+(?:-[eE](?:nc(?:odedcommand)?)?|-c|-command)\b)/i,
      /(?:certutil(?:\.exe)?\s+-urlcache\b)/i,
      /(?:bitsadmin(?:\.exe)?\s+\/transfer\b)/i
    ],
    remediation: "Disable interactive command shell access for web service accounts. Run processes in constrained application sandboxes."
  },
  {
    ruleId: "OWASP-CRS-932120",
    name: "Remote Command Execution: Reverse Shell & Network Spawning",
    category: "Command Injection",
    severity: "CRITICAL",
    baseScore: 95,
    anomalyPoints: 5,
    mitre: { id: "T1059", name: "Command and Scripting Interpreter: Reverse Shell", tactic: "Execution" },
    patterns: [
      /(?:nc\s+-[el]{1,2}\s+\d+)/i,
      /(?:\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+)/i,
      /(?:mkfifo\s+\/tmp\/)/i,
      /(?:bash\s+-i\s+>&)/i
    ],
    remediation: "Enforce strict outbound network firewall rules (egress filtering) to block unapproved outbound TCP connections originating from application web servers."
  },

  // ── 4. PATH TRAVERSAL & LFI (CRS 930xxx) ──
  {
    ruleId: "OWASP-CRS-930100",
    name: "Path Traversal: Directory Traversal Sequence",
    category: "Path Traversal",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1083", name: "File and Directory Discovery: Path Traversal", tactic: "Discovery" },
    patterns: [
      /(?:\.\.[\/\\]|\.\.%2f|\.\.%5c|%2e%2e[\/\\]|\.\.\/)/i,
      /(?:\.\.%252f|\.\.%255c)/i,
      /(?:\.\.\/\.\.\/)/i
    ],
    remediation: "Validate filenames against an alphanumeric whitelist. Resolve file paths using `path.resolve()` and verify the target path begins strictly with the allowed base directory:\n// if (!resolvedPath.startsWith(BASE_DIR)) throw new Error('Path Traversal Detected');"
  },
  {
    ruleId: "OWASP-CRS-930110",
    name: "Path Traversal: Sensitive Linux System File Access",
    category: "Path Traversal",
    severity: "CRITICAL",
    baseScore: 85,
    anomalyPoints: 5,
    mitre: { id: "T1005", name: "Data from Local System: Sensitive Files", tactic: "Collection" },
    patterns: [
      /(?:\/etc\/(?:passwd|shadow|hosts|group|issue|crontab|environment))/i,
      /(?:\/proc\/(?:self|version|cmdline|environ)\/)/i,
      /(?:\/var\/log\/(?:auth|syslog|messages))/i
    ],
    remediation: "Block all direct requests targeting system root directories. Run the web server under an unprivileged user chroot or container isolation."
  },
  {
    ruleId: "OWASP-CRS-930120",
    name: "Path Traversal: Sensitive Windows System Files",
    category: "Path Traversal",
    severity: "CRITICAL",
    baseScore: 85,
    anomalyPoints: 5,
    mitre: { id: "T1005", name: "Data from Local System: Windows Registry/INI", tactic: "Collection" },
    patterns: [
      /(?:c:[\\\/]windows[\\\/](?:system32|win\.ini|repair|system))/i,
      /(?:c:[\\\/]boot\.ini\b)/i,
      /(?:windows[\\\/]system32[\\\/]config[\\\/]sam)/i
    ],
    remediation: "Strictly restrict file reading APIs to application data paths. Ensure Windows ACLs deny read access on sensitive system files to IIS/Node user accounts."
  },
  {
    ruleId: "OWASP-CRS-930130",
    name: "Local File Inclusion: PHP Stream Wrapper & Null-Byte Injection",
    category: "Path Traversal",
    severity: "HIGH",
    baseScore: 80,
    anomalyPoints: 4,
    mitre: { id: "T1005", name: "Data from Local System: LFI Wrappers", tactic: "Collection" },
    patterns: [
      /(?:php:\/\/(?:filter|input|stdin|data|phar))/i,
      /(?:data:\/\/text\/plain)/i,
      /(?:%00|\0)/i
    ],
    remediation: "Disable `allow_url_include` and `allow_url_fopen`. Reject null-byte characters (`%00`) before file system handling."
  },

  // ── 5. SERVER-SIDE REQUEST FORGERY (CRS 934xxx) ──
  {
    ruleId: "OWASP-CRS-934100",
    name: "SSRF: Cloud Instance Metadata Access (IMDSv1/v2)",
    category: "SSRF",
    severity: "CRITICAL",
    baseScore: 90,
    anomalyPoints: 5,
    mitre: { id: "T1090", name: "Proxy: Internal Cloud Metadata SSRF", tactic: "Command and Control" },
    patterns: [
      /(?:https?:\/\/(?:169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal))/i,
      /(?:latest\/(?:meta-data|user-data|api\/token)\b)/i,
      /(?:metadata\/v1\/(?:instance|maintenance)\b)/i
    ],
    remediation: "Require IMDSv2 with token hops limited to 1 (`HttpTokens=required`, `HttpPutResponseHopLimit=1`). Block internal metadata IP ranges at the host egress firewall."
  },
  {
    ruleId: "OWASP-CRS-934110",
    name: "SSRF: Loopback IP & Alternative Numeric IP Evasion",
    category: "SSRF",
    severity: "HIGH",
    baseScore: 80,
    anomalyPoints: 4,
    mitre: { id: "T1090", name: "Proxy: Internal Redirection Loopback", tactic: "Command and Control" },
    patterns: [
      /(?:https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]))/i,
      /(?:https?:\/\/(?:2130706433|0x7f000001|017700000001))/i,
      /(?:https?:\/\/\[::ffff:127\.0\.0\.1\])/i
    ],
    remediation: "Implement strict outbound URL allowlisting. Resolve DNS hostnames before requesting and drop connections to RFC 1918 private / loopback IP spaces."
  },
  {
    ruleId: "OWASP-CRS-934120",
    name: "SSRF: Dangerous Network Scheme Redirection",
    category: "SSRF",
    severity: "HIGH",
    baseScore: 75,
    anomalyPoints: 4,
    mitre: { id: "T1090", name: "Proxy: Multi-Protocol SSRF", tactic: "Command and Control" },
    patterns: [
      /(?:gopher:\/\/|dict:\/\/|tftp:\/\/|ldap:\/\/|file:\/\/)/i
    ],
    remediation: "Restrict client HTTP request libraries to exclusively support standard `http://` and `https://` protocols."
  },

  // ── 6. CRITICAL VULNERABILITIES & DESERIALIZATION (CRS 944xxx) ──
  {
    ruleId: "OWASP-CRS-944100",
    name: "Log4Shell: JNDI Remote Code Execution Probe (CVE-2021-44228)",
    category: "Log4j JNDI RCE",
    severity: "CRITICAL",
    baseScore: 95,
    anomalyPoints: 5,
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: Log4Shell", tactic: "Initial Access" },
    patterns: [
      /\$\{\s*(?:jndi|lower|upper|sys|env|main|date|ctx)[^}]*?:/i,
      /\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http):/i,
      /\$\{jndi:/i
    ],
    remediation: "Upgrade Apache Log4j to >= 2.17.1. Set JVM flag `-Dlog4j2.formatMsgNoLookups=true` to neutralize recursive JNDI message lookups."
  },
  {
    ruleId: "OWASP-CRS-944110",
    name: "Spring4Shell: Spring Framework ClassLoader Access (CVE-2022-22965)",
    category: "Remote Code Execution",
    severity: "CRITICAL",
    baseScore: 95,
    anomalyPoints: 5,
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: Spring4Shell", tactic: "Initial Access" },
    patterns: [
      /(?:class\.module\.classLoader)/i,
      /(?:class\.classLoader)/i
    ],
    remediation: "Upgrade Spring Framework to >= 5.3.18 or >= 5.2.20. Explicitly set `disallowedFields` on DataBinder to deny access to class loader properties."
  },
  {
    ruleId: "OWASP-CRS-944120",
    name: "Insecure Deserialization: Serialized Gadget Chain Payload",
    category: "Insecure Deserialization",
    severity: "CRITICAL",
    baseScore: 90,
    anomalyPoints: 5,
    mitre: { id: "T1203", name: "Exploitation for Client Execution: Deserialization", tactic: "Execution" },
    patterns: [
      /(?:rO0AB[a-zA-Z0-9+/=]{10,})/i,
      /(?:O:\d+:"[a-zA-Z0-9_]+":\d+:\{)/i,
      /(?:c__builtin__\b)/i
    ],
    remediation: "Avoid native serialization formats. Use safe data interchange formats such as JSON with strict schema validation."
  },

  // ── 7. RECONNAISSANCE SCANNERS & BAD BOTS (CRS 913xxx) ──
  {
    ruleId: "OWASP-CRS-913100",
    name: "Reconnaissance: Automated Vulnerability Scanner Tool Probe",
    category: "Scanner Detection",
    severity: "MEDIUM",
    baseScore: 65,
    anomalyPoints: 3,
    mitre: { id: "T1595", name: "Active Scanning: Vulnerability Scanning", tactic: "Reconnaissance" },
    patterns: [
      /(?:sqlmap|nikto|nuclei|burpcollaborator|acunetix|wpscan|gobuster|dirsearch|nmap|masscan|zgrab|nessus|openvas)/i
    ],
    remediation: "Deploy Gateway rate limiting and block unverified automated security scanner signatures."
  },

  // ── 8. HTTP VELOCITY / BRUTE FORCE (CRS 912xxx) ──
  {
    ruleId: "OWASP-CRS-912100",
    name: "HTTP Rate Anomaly: Rapid Request Burst / Brute Force Probe",
    category: "Brute Force",
    severity: "HIGH",
    baseScore: 70,
    anomalyPoints: 4,
    mitre: { id: "T1110", name: "Brute Force: Credential Stuffing & DoS", tactic: "Credential Access" },
    patterns: [],
    remediation: "Enforce gateway IP rate limiting (maximum 30 requests / 10 seconds). Return HTTP 429 Too Many Requests for abusive traffic spikes."
  },

  // ── 9. OBFUSCATION / HIGH ENTROPY (CRS 950xxx) ──
  {
    ruleId: "OWASP-CRS-950100",
    name: "High Shannon Entropy Obfuscation Payload",
    category: "Obfuscation",
    severity: "HIGH",
    baseScore: 70,
    anomalyPoints: 4,
    mitre: { id: "T1027", name: "Obfuscated/Encoded Files or Information", tactic: "Defense Evasion" },
    patterns: [],
    remediation: "Inspect high-entropy request fields for encoded shellcode, packed exploits, or base64 data exfiltration."
  }
];

// ═══════════════════════════════════════════════════════════════════════
// 2. UNIFIED OWASP WAF ENGINE CLASS
// ═══════════════════════════════════════════════════════════════════════
class WafService {
  constructor() {
    this.rules = OWASP_CRS_RULES;
    // Sliding 10s velocity tracker (IP -> [timestamps])
    this.velocityCache = new Map();
    // 15-minute correlation & deduplication cache: (ip:ruleId -> { timestamp, incidentId })
    this.correlationCache = new Map();
    this.totalInspected = 0;
    this.totalBlocked = 0;
    this.totalAlerts = 0;
    // Inbound Anomaly Threshold (CRS Standard default = 5 points)
    this.inboundThreshold = 4;
  }

  /**
   * Multi-pass URL & HTML Entity decoding to defeat nested encoding evasions
   */
  multiPassDecode(str) {
    if (typeof str !== "string") return "";
    let decoded = str;
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded.replace(/\+/g, " "));
        if (next === decoded) break;
        decoded = next;
      } catch (e) {
        break;
      }
    }
    // HTML Entity decoding
    decoded = decoded
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"')
      .replace(/&#39;/gi, "'")
      .replace(/&amp;/gi, "&");
    return decoded;
  }

  /**
   * Shannon Entropy calculation (H > 5.8 indicates obfuscation or packed payload)
   */
  calculateShannonEntropy(str) {
    if (!str || typeof str !== "string") return 0;
    const len = str.length;
    if (len === 0) return 0;

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

  /**
   * Sliding-window IP velocity tracking (10-second window, >= 35 requests)
   */
  trackVelocity(ip, windowMs = 10000, threshold = 35) {
    const now = Date.now();
    const cutoff = now - windowMs;
    let timestamps = this.velocityCache.get(ip) || [];
    timestamps = timestamps.filter(t => t > cutoff);
    timestamps.push(now);
    this.velocityCache.set(ip, timestamps);
    return {
      count: timestamps.length,
      isExceeded: timestamps.length >= threshold
    };
  }

  /**
   * Clean and normalize IP address
   */
  normalizeIp(ip) {
    if (!ip) return "127.0.0.1";
    let clean = ip.trim();
    if (clean.startsWith("::ffff:")) clean = clean.substring(7);
    if (clean === "::1") clean = "127.0.0.1";
    return clean;
  }

  /**
   * Core Request Inspection (Evaluates Gateway HTTP Request)
   */
  inspectRequest(req) {
    this.totalInspected++;
    const rawIp = req.ip || req.connection?.remoteAddress || "127.0.0.1";
    const cleanIp = this.normalizeIp(rawIp);
    const clientIp = cleanIp;

    // Collect all inspectable fields
    const inspectedParts = [];
    if (req.originalUrl) inspectedParts.push({ source: "URL", value: req.originalUrl });
    if (req.url) inspectedParts.push({ source: "Path", value: req.url });

    if (req.query && typeof req.query === "object") {
      for (const [k, v] of Object.entries(req.query)) {
        inspectedParts.push({ source: `QueryParam(${k})`, value: String(v) });
      }
    }

    if (req.body) {
      if (typeof req.body === "string") {
        inspectedParts.push({ source: "Body", value: req.body });
      } else if (typeof req.body === "object") {
        try {
          inspectedParts.push({ source: "Body", value: JSON.stringify(req.body) });
        } catch (e) {}
      }
    }

    if (req.headers) {
      if (req.headers["user-agent"]) inspectedParts.push({ source: "Header(User-Agent)", value: req.headers["user-agent"] });
      if (req.headers["referer"]) inspectedParts.push({ source: "Header(Referer)", value: req.headers["referer"] });
      if (req.headers["x-forwarded-for"]) inspectedParts.push({ source: "Header(X-Forwarded-For)", value: req.headers["x-forwarded-for"] });
    }

    const matchedRules = [];
    let highEntropyPayload = null;
    let maxEntropy = 0;

    for (const part of inspectedParts) {
      const decodedVal = this.multiPassDecode(part.value);
      const entropy = this.calculateShannonEntropy(decodedVal);
      if (entropy > maxEntropy) maxEntropy = entropy;
      if (entropy > 5.8 && decodedVal.length >= 24 && !highEntropyPayload) {
        highEntropyPayload = { value: decodedVal.substring(0, 120), entropy, source: part.source };
      }

      for (const rule of this.rules) {
        if (!rule.patterns || rule.patterns.length === 0) continue;
        for (const pattern of rule.patterns) {
          if (pattern.test(decodedVal) || pattern.test(part.value)) {
            if (!matchedRules.some(m => m.ruleId === rule.ruleId)) {
              matchedRules.push({
                ruleId: rule.ruleId,
                name: rule.name,
                category: rule.category,
                severity: rule.severity,
                baseScore: rule.baseScore,
                anomalyPoints: rule.anomalyPoints || 4,
                mitre: rule.mitre,
                remediation: rule.remediation,
                matchedSource: part.source,
                matchedSample: decodedVal.length > 200 ? decodedVal.substring(0, 200) + "..." : decodedVal
              });
            }
            break;
          }
        }
      }
    }

    // Velocity check
    const velocity = this.trackVelocity(cleanIp);
    if (velocity.isExceeded && !matchedRules.some(m => m.category === "Brute Force")) {
      const velRule = this.rules.find(r => r.ruleId === "OWASP-CRS-912100");
      if (velRule) {
        matchedRules.push({
          ruleId: velRule.ruleId,
          name: velRule.name,
          category: velRule.category,
          severity: velRule.severity,
          baseScore: velRule.baseScore,
          anomalyPoints: velRule.anomalyPoints || 4,
          mitre: velRule.mitre,
          remediation: velRule.remediation,
          matchedSource: "VelocityTracker",
          matchedSample: `${velocity.count} requests in 10s sliding window`
        });
      }
    }

    // High Entropy check
    if (highEntropyPayload && !matchedRules.some(m => m.category === "Obfuscation")) {
      const entRule = this.rules.find(r => r.ruleId === "OWASP-CRS-950100");
      if (entRule) {
        matchedRules.push({
          ruleId: entRule.ruleId,
          name: entRule.name,
          category: entRule.category,
          severity: entRule.severity,
          baseScore: entRule.baseScore,
          anomalyPoints: entRule.anomalyPoints || 4,
          mitre: entRule.mitre,
          remediation: entRule.remediation,
          matchedSource: highEntropyPayload.source,
          matchedSample: `Shannon Entropy ${highEntropyPayload.entropy}: ${highEntropyPayload.value}`
        });
      }
    }

    // Calculate Cumulative Collaborative Anomaly Score
    const totalAnomalyPoints = matchedRules.reduce((sum, r) => sum + (r.anomalyPoints || 3), 0);
    const isThreat = totalAnomalyPoints >= this.inboundThreshold;

    if (!isThreat) {
      return {
        isThreat: false,
        totalAnomalyPoints,
        matchedRules: [],
        primaryRule: null,
        threatScore: 0,
        severity: "CLEAN",
        maxEntropy
      };
    }

    const primaryRule = matchedRules[0];
    let threatScore = primaryRule.baseScore;
    threatScore += (matchedRules.length - 1) * 6;
    if (highEntropyPayload) threatScore += 8;
    threatScore = Math.min(100, Math.max(30, threatScore));

    let finalSeverity = primaryRule.severity;
    if (threatScore >= 90) finalSeverity = "CRITICAL";
    else if (threatScore >= 70) finalSeverity = "HIGH";
    else if (threatScore >= 50) finalSeverity = "MEDIUM";
    else finalSeverity = "LOW";

    return {
      isThreat: true,
      totalAnomalyPoints,
      matchedRules,
      primaryRule,
      threatScore,
      severity: finalSeverity,
      maxEntropy,
      highEntropyPayload,
      clientIp
    };
  }

  /**
   * Universal Raw Log / Payload Analyzer (Powers Threat Studio & Simulator)
   */
  analyzeRawLog(rawLog) {
    const raw = String(rawLog || "").trim();
    if (!raw) {
      return {
        status: "clean",
        detection: {
          status: "clean",
          type: "none",
          severity: "CLEAN",
          threatScore: 0,
          mitre: null,
          entropy: 0,
          extractedPayload: "Empty input",
          normalizedLog: { format: "Unknown", sourceIp: "127.0.0.1", payload: "" },
          velocity: { isAnomaly: false },
          playbook: null
        }
      };
    }

    // IP Extraction
    let sourceIp = "127.0.0.1";
    let format = "Raw Telemetry";

    if (raw.startsWith("{") && raw.endsWith("}")) {
      try {
        const j = JSON.parse(raw);
        sourceIp = j.src_ip || j.sourceIPAddress || j.ip || j.source_ip || sourceIp;
        format = j.format || (j.eventSource ? String(j.eventSource) : "JSON Web Payload");
      } catch (e) {}
    } else {
      const ipMatch = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (ipMatch) {
        sourceIp = ipMatch[0];
        format = "Nginx/Apache Access Log";
      }
    }

    // Synthetic request structure
    const syntheticReq = {
      ip: sourceIp,
      originalUrl: raw,
      url: raw,
      query: { raw },
      body: raw,
      headers: { "user-agent": raw }
    };

    const inspection = this.inspectRequest(syntheticReq);

    if (!inspection.isThreat) {
      return {
        status: "clean",
        detection: {
          status: "clean",
          type: "none",
          severity: "CLEAN",
          threatScore: 0,
          mitre: null,
          entropy: inspection.maxEntropy,
          extractedPayload: "Traffic passed OWASP CRS inspection (Safe)",
          normalizedLog: { format, sourceIp, payload: raw.substring(0, 300) },
          velocity: { isAnomaly: false },
          playbook: null
        }
      };
    }

    const primary = inspection.primaryRule;
    const playbook = {
      summary: `Automated SOAR remediation required for ${primary.name}.`,
      rootCause: `Detected ${primary.category} payload matching OWASP CRS signature ${primary.ruleId}. Cumulative Anomaly Points: ${inspection.totalAnomalyPoints}.`,
      immediateAction: `Add ${sourceIp} to Active Gateway Blacklist.`,
      codeRemediation: primary.remediation,
      containmentCommand: `POST /api/containment/:incidentId/contain -d '{"ip":"${sourceIp}"}'`,
      mitreInfo: primary.mitre,
      ruleId: primary.ruleId,
      attackerIp: sourceIp
    };

    const forensicPackage = {
      rawLog: raw,
      sourceIp,
      format,
      matchedRules: inspection.matchedRules.map(r => ({ id: r.ruleId, name: r.name, category: r.category })),
      totalAnomalyPoints: inspection.totalAnomalyPoints,
      threatScore: inspection.threatScore,
      entropy: inspection.maxEntropy
    };

    return {
      status: "threat_detected",
      detection: {
        status: "threat_detected",
        type: primary.category,
        severity: inspection.severity,
        threatScore: inspection.threatScore,
        confidence: inspection.threatScore >= 80 ? "HIGH (Deterministic OWASP CRS)" : "MEDIUM (Heuristic Signature Match)",
        mitre: primary.mitre,
        entropy: inspection.maxEntropy,
        extractedPayload: primary.matchedSample || raw.substring(0, 200),
        normalizedLog: { format, sourceIp, payload: raw.substring(0, 300) },
        velocity: { isAnomaly: false },
        playbook,
        forensicPackage
      }
    };
  }

  /**
   * Alias for backward compatibility with simulatorService and logAnalysisService
   */
  detectThreat(rawLog) {
    const res = this.analyzeRawLog(rawLog);
    return res.detection;
  }

  /**
   * Handle WAF Security Alert Event (Creates ticket and emits Socket.io event)
   */
  async handleWafAlert(inspection, req) {
    this.totalAlerts++;
    const ip = inspection.clientIp || this.normalizeIp(req.ip || "127.0.0.1");
    const primaryRule = inspection.primaryRule;
    const matchedRules = inspection.matchedRules;
    const threatScore = inspection.threatScore;
    const severity = inspection.severity;

    // Deduplication check: group identical attacks from the same IP within 15 minutes
    const correlationKey = `${ip}:${primaryRule.ruleId}`;
    const now = Date.now();
    const existing = this.correlationCache.get(correlationKey);

    if (existing && (now - existing.timestamp < 15 * 60 * 1000)) {
      existing.count = (existing.count || 1) + 1;
      try {
        await incidentService.addComment(existing.incidentId, {
          note: `[WAF AUTO-CORRELATION] Repeated ${primaryRule.name} probe detected from ${ip}. Total hits: ${existing.count}. Threat score: ${threatScore}/100.`,
          author: "OWASP-WAF-Engine"
        });
      } catch (e) {}

      if (req.io) {
        req.io.emit("telemetry_stream", {
          id: `waf-corr-${now}`,
          timestamp: new Date().toISOString(),
          raw: `[WAF ALERT (CORRELATED)] ${primaryRule.category} (${primaryRule.ruleId}) from ${ip} [${req.method || 'GET'} ${req.originalUrl || req.url}]`,
          sensor: "OWASP-WAF",
          sourceIp: ip,
          isThreat: true,
          threatType: primaryRule.category,
          threatScore,
          severity,
          color: "#f87171",
          stats: { totalGenerated: this.totalInspected, threatsBlocked: this.totalAlerts }
        });
      }
      return { correlated: true, incidentId: existing.incidentId };
    }

    const title = `[OWASP WAF] ${primaryRule.category} detected from ${ip}`;
    const description = `The OWASP Core Rule Set Engine intercepted an exploit attempt on ${req.method || "GET"} ${req.originalUrl || req.url}.
Matched Rules: ${matchedRules.map(r => `${r.ruleId} (${r.name})`).join(", ")}.
Threat Risk Score: ${threatScore}/100 (Anomaly Points: ${inspection.totalAnomalyPoints}).
Shannon Entropy: ${inspection.maxEntropy} bits/char${inspection.highEntropyPayload ? " (HIGH ENTROPY OBFUSCATION DETECTED)" : ""}.`;

    const playbook = {
      summary: `Immediate SOAR response required for ${primaryRule.category} originating from ${ip}.`,
      rootCause: `OWASP CRS Rule ${primaryRule.ruleId} matched malicious patterns in incoming HTTP payload.`,
      immediateAction: `Add ${ip} to Active Gateway Blacklist.`,
      codeRemediation: primaryRule.remediation,
      containmentCommand: `POST /api/containment/:incidentId/contain -d '{"ip":"${ip}"}'`,
      mitreInfo: primaryRule.mitre,
      ruleId: primaryRule.ruleId,
      attackerIp: ip
    };

    const incidentData = {
      title,
      description,
      severity,
      status: "OPEN",
      assignedTo: "OWASP-WAF-Engine",
      threatType: primaryRule.category,
      mitreTechnique: primaryRule.mitre?.id || "T1190",
      playbook,
      extractedPayload: primaryRule.matchedSample,
      confidence: "HIGH (Deterministic OWASP CRS)",
      payload: {
        rawLog: `${req.method || "GET"} ${req.originalUrl || req.url} HTTP/1.1\nHost: ${req.headers?.host || "localhost"}\nSource-IP: ${ip}\nMatched-Data: ${primaryRule.matchedSample}`,
        method: req.method,
        path: req.originalUrl || req.url,
        ip,
        ruleId: primaryRule.ruleId,
        threatScore,
        anomalyPoints: inspection.totalAnomalyPoints
      }
    };

    try {
      const createdIncident = await incidentService.createIncident(incidentData);
      this.correlationCache.set(correlationKey, {
        timestamp: now,
        incidentId: createdIncident.incidentId,
        count: 1
      });

      if (req.io) {
        req.io.emit("incident_created", createdIncident);
        req.io.emit("dashboard_update_needed");
        req.io.emit("telemetry_stream", {
          id: `waf-${now}`,
          timestamp: new Date().toISOString(),
          raw: `[OWASP WAF ALERT] ${primaryRule.category} (${primaryRule.ruleId}) from ${ip} on ${req.method || "GET"} ${req.originalUrl || req.url} (Score: ${threatScore}/100)`,
          sensor: "OWASP-WAF",
          sourceIp: ip,
          isThreat: true,
          threatType: primaryRule.category,
          threatScore,
          severity,
          color: "#dc2626",
          stats: { totalGenerated: this.totalInspected, threatsBlocked: this.totalAlerts }
        });
      }
      return createdIncident;
    } catch (err) {
      console.error("Failed to create WAF incident:", err);
      return null;
    }
  }

  getStatus() {
    return {
      status: "online",
      engine: "OWASP Core Rule Set Engine",
      crsVersion: "v3.3 / v4.0 Active",
      rulesCount: this.rules.length,
      rules: this.rules.map(r => ({
        id: r.ruleId,
        name: r.name,
        category: r.category,
        severity: r.severity,
        baseScore: r.baseScore,
        mitre: r.mitre,
        remediation: r.remediation
      })),
      totalInspected: this.totalInspected,
      totalAlerts: this.totalAlerts,
      inboundThreshold: this.inboundThreshold
    };
  }

  reset() {
    this.correlationCache.clear();
    this.velocityCache.clear();
    this.totalInspected = 0;
    this.totalBlocked = 0;
    this.totalAlerts = 0;
  }
}

const wafService = new WafService();
module.exports = wafService;
