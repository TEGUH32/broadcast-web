const crypto = require('crypto');

class Security {
  static generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  static hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  static sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    // Remove potentially dangerous characters
    return input
      .replace(/[<>]/g, '') // Remove < and >
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  }

  static validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }

  static validatePassword(password) {
    // Minimal 8 karakter, 1 huruf besar, 1 angka
    const re = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    return re.test(password);
  }

  static generateSessionId() {
    return `sess_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`;
  }

  static checkRateLimit(ip, attempts, windowMs = 15 * 60 * 1000) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    const recentAttempts = attempts.filter(attempt => 
      attempt.ip === ip && attempt.timestamp > windowStart
    );
    
    return recentAttempts.length;
  }
}

module.exports = Security;
