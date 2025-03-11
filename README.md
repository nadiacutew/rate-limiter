# KaizenX Akamai - Advanced Rate Limiting & Request Protection

**KaizenX Akamai** is an advanced rate-limiting and request protection module with 30+ features to protect your server from DDoS attacks, abusive requests, and spam.

## Features:
✅ Block suspicious requests based on IP, User-Agent, headers, and patterns.  
✅ Rate limit per IP, user, or route.  
✅ Auto-block malicious requests and permanently ban repeat offenders.  
✅ Detect VPN, Tor, empty User-Agent, and slow attack patterns.  
✅ Auto-unblock after a set duration or keep banned forever.  
✅ Logs blocked requests and allows custom responses.  
✅ Compatible with **Express.js** and other Node.js frameworks.  

---

## 📌 Installation
```sh
npm install kaizenxakamai
```
```js
const express = require('express');
const RateLimiter = require('kaizenxakamai');
const app = express();

// Configuration options for rate limiting
const limiter = new RateLimiter({
  windowMs: 60000, // 1 minute
  maxRequests: 100, // Maximum requests per IP per minute
  blockDuration: 300000, // 5 minutes block
  permanentBlockThreshold: 500, // Permanently block IP after 500 violations
  allowList: ['127.0.0.1'], // Whitelisted IPs
  denyList: ['192.168.1.100'], // Blacklisted IPs
  detectUserAgentAnomalies: true, // Block unusual User-Agents
  blockEmptyUserAgent: true, // Block requests with empty User-Agent
  logBlockedRequests: true, // Log blocked IPs
  blockVPN: false, // Block VPN or proxy users
  blockTor: false, // Block Tor network requests
  blockMaliciousPatterns: true // Detect and block SQLi/XSS attack patterns
});

// Middleware to check rate limits
app.use((req, res, next) => {
  const ip = req.ip;
  if (!limiter.checkRateLimit(ip, req)) {
    return res.status(429).json({ message: 'Too many requests, access denied!' });
  }
  next();
});

app.get('/', (req, res) => {
  res.send('Hello, world!');
});

app.listen(3000, () => console.log('Server running on port 3000'));
```
