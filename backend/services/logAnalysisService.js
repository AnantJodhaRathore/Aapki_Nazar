/**
 * Aapki Nazar - Threat Analysis Adapter Service
 * Delegates directly to the Unified OWASP CRS Engine (wafService.js)
 * ensuring 100% consistency across Gateway, Simulator, and Threat Studio.
 */

const wafService = require("./wafService");

// Simulated Geo-Location Lookup
const GEO_REGIONS = [
  { prefix: "198.51.100", country: "Russia", city: "St. Petersburg", code: "RU", flag: "[RU]" },
  { prefix: "45.33", country: "United States", city: "New York", code: "US", flag: "[US]" },
  { prefix: "103.251", country: "China", city: "Beijing", code: "CN", flag: "[CN]" },
  { prefix: "185", country: "Brazil", city: "Sao Paulo", code: "BR", flag: "[BR]" },
  { prefix: "194.26", country: "Iran", city: "Tehran", code: "IR", flag: "[IR]" },
  { prefix: "203.0.113", country: "North Korea", city: "Pyongyang", code: "KP", flag: "[KP]" },
  { prefix: "10.0", country: "Internal Cloud", city: "VPC-East", code: "AWS", flag: "[AWS]" },
  { prefix: "172.16", country: "Internal Gateway", city: "DC-Core", code: "CORP", flag: "[CORP]" }
];

function getSimulatedGeo(ip) {
  if (!ip || ip === "unknown" || ip === "127.0.0.1" || ip === "::1") {
    return { country: "Localhost", city: "Loopback", code: "LOCAL", flag: "[LOCAL]" };
  }
  for (const region of GEO_REGIONS) {
    if (ip.startsWith(region.prefix)) return region;
  }
  return { country: "Global Internet", city: "External Host", code: "WAN", flag: "[WAN]" };
}

function detectThreat(rawLog) {
  const analysis = wafService.detectThreat(rawLog);
  if (analysis && analysis.normalizedLog) {
    analysis.normalizedLog.geo = getSimulatedGeo(analysis.normalizedLog.sourceIp);
  }
  return analysis;
}

module.exports = {
  detectThreat,
  getSimulatedGeo
};
