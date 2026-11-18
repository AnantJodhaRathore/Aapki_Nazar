const express = require("express");
const wafService = require("../services/wafService");
const crsIngestionService = require("../services/crsIngestionService");

const router = express.Router();

const OFFICIAL_CRS_FAMILIES = [
  {
    family: "REQUEST-942",
    name: "Application Attack: SQL Injection (SQLi)",
    ruleRange: "942000 - 942999",
    ruleCount: 88,
    severity: "CRITICAL (Anomaly Score: 5)",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: SQLi", tactic: "Initial Access" },
    description: "Evaluates SQL syntax, boolean tautologies, stacked queries, union injection, libinjection tokenization, and blind sleep heuristics."
  },
  {
    family: "REQUEST-941",
    name: "Application Attack: Cross-Site Scripting (XSS)",
    ruleRange: "941000 - 941999",
    ruleCount: 76,
    severity: "HIGH (Anomaly Score: 5)",
    mitre: { id: "T1059.007", name: "Command and Scripting: JavaScript", tactic: "Execution" },
    description: "Detects script tags, SVG/event handler attributes, DOM injection, Javascript URI schemes, and libinjection XSS vectors."
  },
  {
    family: "REQUEST-932",
    name: "Application Attack: Remote Code Execution (RCE / CMDi)",
    ruleRange: "932000 - 932999",
    ruleCount: 64,
    severity: "CRITICAL (Anomaly Score: 5)",
    mitre: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    description: "Detects command chaining operators (; | & `), shell binaries (sh, bash, powershell), environment variable expansion, and payload pipes."
  },
  {
    family: "REQUEST-930",
    name: "Application Attack: Path Traversal / Local File Inclusion (LFI)",
    ruleRange: "930000 - 930999",
    ruleCount: 22,
    severity: "HIGH (Anomaly Score: 5)",
    mitre: { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
    description: "Identifies directory traversal sequences (../, ..\\), null byte injections, access to /etc/passwd, /etc/shadow, win.ini, and sensitive OS files."
  },
  {
    family: "REQUEST-931",
    name: "Application Attack: Remote File Inclusion (RFI)",
    ruleRange: "931000 - 931999",
    ruleCount: 16,
    severity: "CRITICAL (Anomaly Score: 5)",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application: RFI", tactic: "Initial Access" },
    description: "Detects remote URI inclusions (http://, https://, ftp://, php://input) inside query parameters and upload fields."
  },
  {
    family: "REQUEST-934",
    name: "Application Attack: Node.js / SSRF Injection",
    ruleRange: "934000 - 934999",
    ruleCount: 18,
    severity: "HIGH (Anomaly Score: 5)",
    mitre: { id: "T1090", name: "Proxy: Multi-Protocol SSRF", tactic: "Command and Control" },
    description: "Detects cloud metadata service probes (169.254.169.254), loopback interfaces, dangerous network URI schemes (gopher, tftp, dict)."
  },
  {
    family: "REQUEST-944",
    name: "Application Attack: JAVA / Deserialization / Log4Shell",
    ruleRange: "944000 - 944999",
    ruleCount: 24,
    severity: "CRITICAL (Anomaly Score: 5)",
    mitre: { id: "T1190", name: "Log4Shell & Deserialization Gadgets", tactic: "Initial Access" },
    description: "Detects JNDI lookups (${jndi:ldap://...}), Java serialized objects (rO0AB), Spring4Shell class loader access, and deserialization streams."
  },
  {
    family: "REQUEST-913",
    name: "Scanner & Bad Bot Detection",
    ruleRange: "913000 - 913999",
    ruleCount: 30,
    severity: "MEDIUM (Anomaly Score: 3)",
    mitre: { id: "T1595", name: "Active Scanning: Vulnerability Scanners", tactic: "Reconnaissance" },
    description: "Flags vulnerability scanners such as sqlmap, nikto, nuclei, gobuster, acunetix, burp suite collaborator, nmap, masscan, and automated probes."
  },
  {
    family: "REQUEST-920",
    name: "Protocol Enforcement & HTTP RFC Validation",
    ruleRange: "920000 - 920999",
    ruleCount: 52,
    severity: "MEDIUM (Anomaly Score: 3)",
    mitre: { id: "T1190", name: "Protocol Anomaly & Smuggling", tactic: "Defense Evasion" },
    description: "Enforces strict RFC specifications for request lines, header formatting, character encoding bounds, content-length validation, and method limits."
  },
  {
    family: "REQUEST-949",
    name: "Anomaly Evaluation & Blocking Decision Engine",
    ruleRange: "949000 - 949999",
    ruleCount: 10,
    severity: "CRITICAL (Decision Threshold: 5)",
    mitre: { id: "T1190", name: "Automated Blocking Enforcement", tactic: "Defense" },
    description: "Computes total collaborative inbound anomaly score. If score >= 5, triggers rule 949110 and halts transaction with HTTP 403 Forbidden."
  }
];

router.get("/", (req, res) => {
  try {
    const crsStatus = crsIngestionService.getStatus();
    const customStatus = wafService.getStatus();

    const customRules = wafService.rules.map(r => ({
      id: r.ruleId,
      name: r.name,
      category: r.category,
      severity: r.severity,
      baseScore: r.baseScore,
      mitre: r.mitre,
      remediation: r.remediation
    }));

    res.json({
      officialCrs: {
        engine: "Official OWASP Core Rule Set (CRS)",
        version: crsStatus.versions?.crsVersion || "OWASP_CRS/4.30.0",
        setupVersion: crsStatus.versions?.crsSetupVersion || "4300",
        modsecVersion: crsStatus.versions?.modsecVersion || "ModSecurity v3.0.17",
        nginxVersion: crsStatus.versions?.nginxVersion || "nginx/1.30.6",
        upstreamRuleFiles: crsStatus.versions?.upstreamRuleFiles || 27,
        upstreamSecRulesCount: crsStatus.versions?.upstreamSecRulesCount || 675,
        ruleCountNote: "675 upstream SecRule directives defined across 27 files (active execution governed by Paranoia Level 1)",
        gatewayStatus: crsStatus.gateway?.status || "UNKNOWN",
        isGatewayVerified: crsStatus.gateway?.isVerifiedGateway || false,
        gatewayUrl: crsStatus.gateway?.url || "http://localhost:8080",
        anomalyInboundThreshold: crsStatus.versions?.inboundAnomalyThreshold || 5,
        blockingParanoiaLevel: crsStatus.versions?.paranoiaLevel || 1,
        ruleFamilies: OFFICIAL_CRS_FAMILIES
      },
      customSensor: {
        engine: "Aapki Nazar Novelty Engine (Custom Signatures)",
        count: customRules.length,
        rules: customRules
      }
    });
  } catch (err) {
    console.error("Failed to load rules catalog:", err);
    res.status(500).json({ error: "Failed to load rules catalog" });
  }
});

module.exports = router;
