const database = require('../utils/database');
const Security = require('../utils/security');

// ===== AUTHENTICATION MIDDLEWARE =====
const authenticate = async (req, res, next) => {
  try {
    // Check session first
    if (!req.session || !req.session.userId || !req.session.sessionId) {
      // Check for remember me token if session doesn't exist
      return checkRememberMe(req, res, next);
    }

    // Validate session in database
    const session = await database.validateSession(req.session.sessionId);
    if (!session) {
      // Check if there's a remember me token before destroying session
      if (req.cookies && req.cookies.remember_me) {
        req.session = null; // Clear session but don't destroy yet
        return checkRememberMe(req, res, next);
      }
      
      req.session.destroy();
      return res.status(401).json({ 
        success: false, 
        message: 'Sesi telah kedaluwarsa' 
      });
    }

    // Check session expiry (e.g., 24 hours)
    const sessionAge = Date.now() - new Date(session.createdAt).getTime();
    const maxSessionAge = 24 * 60 * 60 * 1000; // 24 hours
    
    if (sessionAge > maxSessionAge) {
      await database.deleteSession(req.session.sessionId);
      
      if (req.cookies && req.cookies.remember_me) {
        req.session = null;
        return checkRememberMe(req, res, next);
      }
      
      req.session.destroy();
      return res.status(401).json({ 
        success: false, 
        message: 'Sesi telah kedaluwarsa, silakan login ulang' 
      });
    }

    // Check user exists and is active
    const user = await database.findUserById(req.session.userId);
    if (!user || !user.isActive) {
      await database.deleteSession(req.session.sessionId);
      req.session.destroy();
      clearRememberMeCookie(res);
      
      return res.status(401).json({ 
        success: false, 
        message: 'Akun tidak ditemukan atau tidak aktif' 
      });
    }

    // Update last active
    await database.updateSessionActivity(req.session.sessionId);
    req.session.lastActive = Date.now();
    
    // Attach user to request (without sensitive data)
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      phone: user.phone,
      isVerified: user.isVerified,
      isAdmin: user.isAdmin || false,
      role: user.role || 'user',
      pairingStatus: user.pairingStatus || 'unpaired',
      profile: user.profile || {}
    };
    
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Kesalahan autentikasi' 
    });
  }
};

// ===== REMEMBER ME HELPER FUNCTION =====
const checkRememberMe = async (req, res, next) => {
  try {
    if (!req.cookies || !req.cookies.remember_me) {
      return res.status(401).json({ 
        success: false, 
        message: 'Sesi tidak valid, silakan login ulang' 
      });
    }

    const rememberToken = req.cookies.remember_me;
    const user = await database.findUserByRememberToken(rememberToken);
    
    if (!user || !user.isActive) {
      clearRememberMeCookie(res);
      return res.status(401).json({ 
        success: false, 
        message: 'Token remember me tidak valid' 
      });
    }

    // Check token expiry (e.g., 30 days)
    if (user.rememberExpires && new Date(user.rememberExpires) < new Date()) {
      await database.clearRememberToken(user.id);
      clearRememberMeCookie(res);
      return res.status(401).json({ 
        success: false, 
        message: 'Token remember me telah kedaluwarsa' 
      });
    }

    // Create new session
    const sessionId = Security.generateSessionId();
    await database.createSession(user.id, sessionId, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      isVerified: user.isVerified
    });

    // Set session
    req.session.userId = user.id;
    req.session.sessionId = sessionId;
    req.session.lastActive = Date.now();

    // Attach user to request
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      phone: user.phone,
      isVerified: user.isVerified,
      isAdmin: user.isAdmin || false,
      role: user.role || 'user',
      pairingStatus: user.pairingStatus || 'unpaired',
      profile: user.profile || {}
    };

    next();
  } catch (error) {
    console.error('Remember me error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Kesalahan autentikasi' 
    });
  }
};

// ===== CLEAR REMEMBER ME COOKIE HELPER =====
const clearRememberMeCookie = (res) => {
  res.clearCookie('remember_me', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
};

// ===== PAIRING MIDDLEWARE =====
const requirePairing = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Tidak terautentikasi' 
      });
    }

    // Check if user is verified (paired)
    if (!req.user.isVerified || req.user.pairingStatus !== 'paired') {
      // Check if there's a pending pairing request
      const pendingPairing = await database.getPendingPairing(req.user.id);
      
      if (pendingPairing) {
        return res.status(403).json({ 
          success: false, 
          message: 'Menunggu konfirmasi pairing WhatsApp',
          requiresPairing: true,
          pairingStatus: 'pending',
          pairingId: pendingPairing.id,
          pairingExpires: pendingPairing.expiresAt
        });
      }
      
      return res.status(403).json({ 
        success: false, 
        message: 'Pairing WhatsApp diperlukan',
        requiresPairing: true,
        pairingStatus: 'unpaired'
      });
    }
    
    next();
  } catch (error) {
    console.error('Pairing check error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Kesalahan pemeriksaan pairing' 
    });
  }
};

// ===== CHECK PAIRING STATUS =====
const checkPairingStatus = async (req, res, next) => {
  try {
    if (!req.user) {
      return next();
    }

    req.user.pairingStatus = req.user.pairingStatus || 'unpaired';
    req.user.pairingRequired = !req.user.isVerified || req.user.pairingStatus !== 'paired';
    
    next();
  } catch (error) {
    console.error('Pairing status check error:', error);
    next();
  }
};

// ===== ADMIN ONLY MIDDLEWARE =====
const adminOnly = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      success: false, 
      message: 'Tidak terautentikasi' 
    });
  }

  if (!req.user.isAdmin) {
    return res.status(403).json({ 
      success: false, 
      message: 'Akses hanya untuk administrator' 
    });
  }

  next();
};

// ===== ROLE-BASED AUTHORIZATION =====
const authorize = (roles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Tidak terautentikasi' 
      });
    }

    // Convert roles to array if string
    const allowedRoles = Array.isArray(roles) ? roles : [roles];
    
    // Allow admin to bypass role checks
    if (req.user.isAdmin) {
      return next();
    }

    // Check if user has required role
    if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Akses ditolak. Peran tidak memadai.' 
      });
    }

    next();
  };
};

// ===== RATE LIMITING MIDDLEWARE =====
const rateLimitMiddleware = (maxRequests, timeWindow) => {
  const requests = new Map();
  
  return async (req, res, next) => {
    const key = req.user ? `${req.user.id}:${req.path}` : `${req.ip}:${req.path}`;
    const now = Date.now();
    
    if (!requests.has(key)) {
      requests.set(key, []);
    }
    
    const userRequests = requests.get(key);
    const windowStart = now - timeWindow;
    
    // Remove old requests
    while (userRequests.length > 0 && userRequests[0] < windowStart) {
      userRequests.shift();
    }
    
    // Check rate limit
    if (userRequests.length >= maxRequests) {
      return res.status(429).json({ 
        success: false, 
        message: 'Terlalu banyak permintaan. Silakan coba lagi nanti.',
        retryAfter: Math.ceil((userRequests[0] + timeWindow - now) / 1000)
      });
    }
    
    // Add current request
    userRequests.push(now);
    
    // Log rate limit for admins
    if (req.user && req.user.isAdmin && userRequests.length > maxRequests * 0.8) {
      console.log(`Rate limit warning for ${key}: ${userRequests.length}/${maxRequests}`);
    }
    
    next();
  };
};

// ===== API KEY AUTHENTICATION =====
const apiKeyAuth = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    
    if (!apiKey) {
      return res.status(401).json({ 
        success: false, 
        message: 'API key diperlukan' 
      });
    }

    const apiKeyData = await database.validateApiKey(apiKey);
    
    if (!apiKeyData || !apiKeyData.isActive) {
      return res.status(401).json({ 
        success: false, 
        message: 'API key tidak valid' 
      });
    }

    // Check rate limit for API key
    const usage = await database.checkApiKeyUsage(apiKeyData.key);
    if (usage >= apiKeyData.rateLimit) {
      return res.status(429).json({ 
        success: false, 
        message: 'Batas penggunaan API key tercapai' 
      });
    }

    // Increment usage
    await database.incrementApiKeyUsage(apiKeyData.key);
    
    // Attach API key info to request
    req.apiKey = apiKeyData;
    
    // If API key is associated with a user, attach user info
    if (apiKeyData.userId) {
      const user = await database.findUserById(apiKeyData.userId);
      if (user && user.isActive) {
        req.user = {
          id: user.id,
          username: user.username,
          email: user.email,
          isAdmin: user.isAdmin || false,
          role: user.role || 'user',
          isApiRequest: true
        };
      }
    }
    
    next();
  } catch (error) {
    console.error('API key auth error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Kesalahan autentikasi API' 
    });
  }
};

// ===== CSRF PROTECTION =====
const csrfProtection = (req, res, next) => {
  // Skip for safe methods and API requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || req.user?.isApiRequest) {
    return next();
  }
  
  // Check CSRF token
  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
  const sessionToken = req.session.csrfToken;
  
  if (!csrfToken || !sessionToken || csrfToken !== sessionToken) {
    return res.status(403).json({
      success: false,
      message: 'Token CSRF tidak valid'
    });
  }
  
  // Regenerate CSRF token for next request
  req.session.csrfToken = Security.generateCsrfToken();
  
  next();
};

// ===== LOGGING MIDDLEWARE =====
const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // Log request details
  const logData = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    sessionId: req.session?.sessionId
  };
  
  console.log('Request:', logData);
  
  // Log response
  const originalSend = res.send;
  res.send = function(body) {
    const duration = Date.now() - startTime;
    
    const responseLog = {
      ...logData,
      duration: `${duration}ms`,
      statusCode: res.statusCode,
      responseSize: body ? Buffer.byteLength(body.toString()) : 0
    };
    
    console.log('Response:', responseLog);
    
    // Log to database for important requests
    if (req.user && ['POST', 'PUT', 'DELETE'].includes(req.method)) {
      database.logRequest({
        ...logData,
        duration,
        statusCode: res.statusCode,
        userId: req.user.id
      }).catch(err => console.error('Failed to log request:', err));
    }
    
    return originalSend.call(this, body);
  };
  
  next();
};

// ===== VALIDATION MIDDLEWARE =====
const validateRequest = (schema) => {
  return (req, res, next) => {
    const dataToValidate = req.method === 'GET' ? req.query : req.body;
    
    const { error, value } = schema.validate(dataToValidate, {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: req.method === 'GET'
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message.replace(/['"]/g, '')
      }));
      
      return res.status(400).json({
        success: false,
        message: 'Validasi gagal',
        errors
      });
    }
    
    // Assign validated data
    if (req.method === 'GET') {
      req.query = value;
    } else {
      req.body = value;
    }
    
    next();
  };
};

// ===== FILE UPLOAD VALIDATION =====
const validateFileUpload = (options = {}) => {
  const {
    maxSize = 5 * 1024 * 1024,
    allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'],
    maxFiles = 1
  } = options;
  
  return (req, res, next) => {
    if (!req.files || Object.keys(req.files).length === 0) {
      return next();
    }
    
    const files = Array.isArray(req.files) ? req.files : Object.values(req.files).flat();
    
    if (files.length > maxFiles) {
      return res.status(400).json({
        success: false,
        message: `Maksimal ${maxFiles} file yang diizinkan`
      });
    }
    
    for (const file of files) {
      if (file.size > maxSize) {
        return res.status(400).json({
          success: false,
          message: `File ${file.name} terlalu besar. Maksimal ${maxSize / (1024 * 1024)}MB`
        });
      }
      
      if (!allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({
          success: false,
          message: `Tipe file ${file.name} tidak diizinkan`
        });
      }
    }
    
    next();
  };
};

// ===== EXPORT ALL MIDDLEWARES =====
module.exports = {
  authenticate,
  requirePairing,
  checkPairingStatus,
  adminOnly,
  authorize,
  rateLimitMiddleware,
  apiKeyAuth,
  csrfProtection,
  requestLogger,
  validateRequest,
  validateFileUpload,
  
  // Helper for clearing remember me cookie
  clearRememberMeCookie
};
