/**
 * Aapki Nazar - Active SOAR Gateway Containment Service
 * Manages live IP blacklisting, state persistence, and active 403 enforcement.
 */

class ContainmentService {
  constructor() {
    // Map of ip -> { ip, blockedAt, reason, incidentId, blockedBy }
    this.blacklist = new Map();
  }

  normalizeIp(ip) {
    if (!ip) return "127.0.0.1";
    let clean = ip.trim();
    if (clean.startsWith("::ffff:")) {
      clean = clean.substring(7);
    }
    if (clean === "::1") {
      clean = "127.0.0.1";
    }
    return clean;
  }

  /**
   * Add IP to active gateway blacklist
   */
  blockIp(ip, reason = "Contained by Aapki Nazar SOC", incidentId = null, blockedBy = "SOC-Analyst") {
    const cleanIp = this.normalizeIp(ip);
    const record = {
      ip: cleanIp,
      blockedAt: new Date().toISOString(),
      reason,
      incidentId: incidentId || "INC-MANUAL",
      blockedBy
    };
    this.blacklist.set(cleanIp, record);
    console.log(`[GATEWAY FIREWALL] IP ${cleanIp} added to active blacklist. Reason: ${reason}`);
    return record;
  }

  /**
   * Remove IP from active gateway blacklist
   */
  unblockIp(ip) {
    const cleanIp = this.normalizeIp(ip);
    const existed = this.blacklist.delete(cleanIp);
    if (existed) {
      console.log(`[GATEWAY FIREWALL] IP ${cleanIp} removed from active blacklist.`);
    }
    return existed;
  }

  /**
   * Check if IP is currently contained
   */
  isIpBlocked(ip) {
    const cleanIp = this.normalizeIp(ip);
    return this.blacklist.has(cleanIp);
  }

  /**
   * Retrieve block record
   */
  getBlockDetails(ip) {
    const cleanIp = this.normalizeIp(ip);
    return this.blacklist.get(cleanIp) || null;
  }

  /**
   * Get all active contained IPs
   */
  getAllBlockedIps() {
    return Array.from(this.blacklist.values());
  }

  /**
   * Clear all (for testing)
   */
  clear() {
    this.blacklist.clear();
  }
}

const containmentService = new ContainmentService();
module.exports = containmentService;
