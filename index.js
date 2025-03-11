const fs = require('fs');

class RateLimiter {
  constructor(options) {
    this.options = {
      windowMs: options.windowMs || 60000, // Default 1 menit
      maxRequests: options.maxRequests || 100, // Maksimal request
      blockDuration: options.blockDuration || 300000, // Default 5 menit
      permanentBlockThreshold: options.permanentBlockThreshold || 500, // Batas blokir permanen
      spamRequestThreshold: options.spamRequestThreshold || 10, // Batas spam request
      allowList: new Set(options.allowList || []), // IP yang selalu diizinkan
      denyList: new Set(options.denyList || []), // IP yang selalu diblokir
      logBlockedRequests: options.logBlockedRequests || false,
      logPath: options.logPath || 'blocked_ips.log',
      blockVPN: options.blockVPN || false,
      blockTor: options.blockTor || false,
      customResponseCode: options.customResponseCode || 429,
      customResponseMessage: options.customResponseMessage || 'Too many requests, try again later.',
      autoUnblock: options.autoUnblock || true,
      maxPayloadSize: options.maxPayloadSize || 1048576, // 1MB
      strictMode: options.strictMode || false,
      detectUserAgentAnomalies: options.detectUserAgentAnomalies || false,
      allowedUserAgents: options.allowedUserAgents || [],
      blockEmptyUserAgent: options.blockEmptyUserAgent || false,
      blockByHeader: options.blockByHeader || [],
      blockByMethod: options.blockByMethod || [],
      rateLimitPerRoute: options.rateLimitPerRoute || {},
      rateLimitPerUser: options.rateLimitPerUser || {},
      challengeMode: options.challengeMode || false,
      blockMaliciousPatterns: options.blockMaliciousPatterns || false,
      blockSlowloris: options.blockSlowloris || false,
      autoAdjustRateLimit: options.autoAdjustRateLimit || false,
      banForever: options.banForever || false,
    };

    this.store = new Map();
    this.blockedIPs = new Set();
    this.permanentBlockedIPs = new Set();
  }

  checkRateLimit(ip, req) {
    if (this.options.allowList.has(ip)) return true;
    if (this.options.denyList.has(ip) || this.blockedIPs.has(ip) || this.permanentBlockedIPs.has(ip)) return false;

    const now = Date.now();
    const windowStart = now - this.options.windowMs;
    const requestData = this.store.get(ip) || [];

    const validRequests = requestData.filter(timestamp => timestamp > windowStart);
    this.store.set(ip, validRequests);

    if (validRequests.length < this.options.maxRequests) {
      this.store.get(ip).push(now);
      return true;
    } else {
      if (validRequests.length >= this.options.permanentBlockThreshold) {
        this.permanentBlockedIPs.add(ip);
        if (this.options.logBlockedRequests) this.logBlock(ip, 'PERMANENT');
      } else {
        this.blockIP(ip);
      }
      return false;
    }
  }

  blockIP(ip) {
    this.blockedIPs.add(ip);
    if (this.options.logBlockedRequests) this.logBlock(ip, 'TEMPORARY');
    if (this.options.autoUnblock) {
      setTimeout(() => this.blockedIPs.delete(ip), this.options.blockDuration);
    }
  }

  logBlock(ip, type) {
    const logMessage = `${new Date().toISOString()} - BLOCKED ${type}: ${ip}\n`;
    fs.appendFileSync(this.options.logPath, logMessage);
  }
}

module.exports = RateLimiter;
