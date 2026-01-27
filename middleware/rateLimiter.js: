const database = require('../utils/database');

class RateLimiter {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
    this.maxRequests = options.maxRequests || 100;
    this.requests = new Map();
  }

  async check(userId, endpoint) {
    const key = `${userId}:${endpoint}`;
    const now = Date.now();
    const windowStart = now - this.windowMs;

    if (!this.requests.has(key)) {
      this.requests.set(key, []);
    }

    const userRequests = this.requests.get(key);
    
    // Remove old requests
    while (userRequests.length > 0 && userRequests[0] < windowStart) {
      userRequests.shift();
    }

    // Check rate limit
    if (userRequests.length >= this.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: new Date(userRequests[0] + this.windowMs)
      };
    }

    // Add current request
    userRequests.push(now);

    return {
      allowed: true,
      remaining: this.maxRequests - userRequests.length - 1,
      resetTime: new Date(now + this.windowMs)
    };
  }

  cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    for (const [key, requests] of this.requests.entries()) {
      while (requests.length > 0 && requests[0] < windowStart) {
        requests.shift();
      }
      
      if (requests.length === 0) {
        this.requests.delete(key);
      }
    }
  }
}

// Cleanup old requests every minute
const rateLimiter = new RateLimiter();
setInterval(() => rateLimiter.cleanup(), 60 * 1000);

module.exports = rateLimiter;
