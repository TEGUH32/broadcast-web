const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const database = require('../utils/database');
const Security = require('../utils/security');
const { emailService } = require('../utils/email');
const { rateLimitMiddleware, validateRequest } = require('../middleware/auth');
const Joi = require('joi');

// ===== RATE LIMITING =====
const registerLimiter = rateLimitMiddleware(3, 60 * 60 * 1000); // 3 registrations per hour per IP
const loginLimiter = rateLimitMiddleware(5, 15 * 60 * 1000); // 5 login attempts per 15 minutes
const sessionLimiter = rateLimitMiddleware(100, 15 * 60 * 1000); // 100 session checks per 15 minutes

// ===== VALIDATION SCHEMAS =====
const registerSchema = Joi.object({
  username: Joi.string()
    .min(3)
    .max(30)
    .pattern(/^[a-zA-Z0-9_]+$/)
    .required()
    .messages({
      'string.pattern.base': 'Username hanya boleh berisi huruf, angka, dan underscore',
      'string.min': 'Username minimal 3 karakter',
      'string.max': 'Username maksimal 30 karakter'
    }),
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Format email tidak valid'
    }),
  password: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .required()
    .messages({
      'string.min': 'Password minimal 8 karakter',
      'string.pattern.base': 'Password harus mengandung huruf besar, huruf kecil, dan angka'
    }),
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Konfirmasi password tidak cocok'
    }),
  phone: Joi.string()
    .pattern(/^[0-9]{10,15}$/)
    .optional()
    .messages({
      'string.pattern.base': 'Nomor telepon harus 10-15 digit angka'
    }),
  agreeToTerms: Joi.boolean()
    .valid(true)
    .required()
    .messages({
      'any.only': 'Anda harus menyetujui syarat dan ketentuan'
    })
});

const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required(),
  rememberMe: Joi.boolean().default(false)
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

const resetPasswordSchema = Joi.object({
  token: Joi.string().required(),
  newPassword: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .required(),
  confirmPassword: Joi.string()
    .valid(Joi.ref('newPassword'))
    .required()
});

// ===== PUBLIC ROUTES =====

// Home page
router.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard.html');
  }
  
  // Render landing page with CSRF token
  res.render('index', {
    csrfToken: req.csrfToken ? req.csrfToken() : '',
    user: req.session.user || null,
    appName: process.env.APP_NAME || 'WhatsApp Broadcast Bot',
    appDescription: 'Sistem broadcast WhatsApp otomatis dengan pairing code verification'
  });
});

// Landing page API data
router.get('/api/landing-stats', async (req, res) => {
  try {
    const stats = {
      totalUsers: database.data.users?.length || 0,
      totalBroadcasts: database.data.broadcasts?.length || 0,
      activeUsers: database.data.users?.filter(u => u.isActive)?.length || 0,
      successRate: '98%'
    };
    
    res.json({ success: true, data: stats });
  } catch (error) {
    res.json({ 
      success: true, 
      data: { 
        totalUsers: 1000, 
        totalBroadcasts: 5000,
        activeUsers: 850,
        successRate: '98%'
      } 
    });
  }
});

// ===== AUTHENTICATION ROUTES =====

// Register
router.post('/register', registerLimiter, validateRequest(registerSchema), async (req, res) => {
  try {
    const { username, email, password, phone } = req.body;

    // Check if username already exists
    const existingUsername = await database.findUser(username);
    if (existingUsername) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username sudah digunakan',
        field: 'username'
      });
    }

    // Check if email already exists
    const existingEmail = await database.findUserByEmail(email);
    if (existingEmail) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email sudah terdaftar',
        field: 'email'
      });
    }

    // Check if phone already exists
    if (phone) {
      const existingPhone = await database.findUserByPhone(phone);
      if (existingPhone) {
        return res.status(400).json({ 
          success: false, 
          message: 'Nomor telepon sudah terdaftar',
          field: 'phone'
        });
      }
    }

    // Create user
    const user = await database.createUser(
      Security.sanitizeInput(username),
      password,
      Security.sanitizeInput(email),
      phone
    );

    // Log registration
    await database.logRequest({
      method: 'POST',
      url: '/register',
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: user.id,
      metadata: {
        username: user.username,
        email: user.email
      }
    });

    // Send welcome email
    try {
      await emailService.sendWelcomeEmail(user);
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
      // Don't fail registration if email fails
    }

    // Create session
    const sessionId = Security.generateSessionId();
    await database.createSession(user.id, sessionId, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      isVerified: user.isVerified
    });

    req.session.userId = user.id;
    req.session.sessionId = sessionId;
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      isVerified: user.isVerified,
      isAdmin: user.isAdmin || false,
      needsPairing: !user.isVerified
    };

    // Set remember me cookie if requested
    if (req.body.rememberMe) {
      res.cookie('remember_me', user.rememberToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        sameSite: 'strict',
        path: '/'
      });
    }

    res.json({ 
      success: true, 
      message: 'Registrasi berhasil! Silakan cek email Anda untuk panduan selanjutnya.',
      data: { 
        userId: user.id,
        username: user.username,
        needsPairing: !user.isVerified,
        redirectTo: '/pairing.html'
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    
    // Log failed registration
    await database.logLoginAttempt(
      req.body.username || 'unknown',
      req.ip,
      false,
      'registration_failed',
      error.message
    );
    
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat registrasi. Silakan coba lagi nanti.' 
    });
  }
});

// Login
router.post('/login', loginLimiter, validateRequest(loginSchema), async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;

    // Log login attempt
    await database.logLoginAttempt(username, req.ip, false, 'attempt');

    // Find user by username or email
    const user = await database.findUser(username) || await database.findUserByEmail(username);
    
    if (!user) {
      await database.logLoginAttempt(username, req.ip, false, 'user_not_found');
      return res.status(401).json({ 
        success: false, 
        message: 'Username atau password salah' 
      });
    }

    // Verify password
    const isValid = await database.verifyPassword(user, password);
    if (!isValid) {
      await database.logLoginAttempt(username, req.ip, false, 'wrong_password');
      return res.status(401).json({ 
        success: false, 
        message: 'Username atau password salah' 
      });
    }

    // Check if user is active
    if (!user.isActive) {
      await database.logLoginAttempt(username, req.ip, false, 'account_inactive');
      return res.status(403).json({ 
        success: false, 
        message: 'Akun dinonaktifkan. Silakan hubungi administrator.' 
      });
    }

    // Check if user is locked (too many failed attempts)
    const failedAttempts = await database.getLoginAttempts(req.ip, 15 * 60 * 1000);
    const recentFailed = failedAttempts.filter(a => !a.success);
    
    if (recentFailed.length >= 5) {
      await database.logLoginAttempt(username, req.ip, false, 'rate_limited');
      return res.status(429).json({ 
        success: false, 
        message: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.' 
      });
    }

    // Create session
    const sessionId = Security.generateSessionId();
    await database.createSession(user.id, sessionId, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      isVerified: user.isVerified
    });

    // Update user last login
    await database.updateUserLastLogin(user.id);

    req.session.userId = user.id;
    req.session.sessionId = sessionId;
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      isVerified: user.isVerified,
      isAdmin: user.isAdmin || false,
      pairingStatus: user.pairingStatus || 'unpaired',
      needsPairing: !user.isVerified
    };

    // Set remember me cookie
    if (rememberMe) {
      res.cookie('remember_me', user.rememberToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        sameSite: 'strict',
        path: '/'
      });
    }

    // Log successful login
    await database.logLoginAttempt(username, req.ip, true, 'success');

    res.json({ 
      success: true, 
      message: 'Login berhasil!',
      data: { 
        userId: user.id,
        username: user.username,
        isVerified: user.isVerified,
        pairingStatus: user.pairingStatus || 'unpaired',
        needsPairing: !user.isVerified,
        redirectTo: user.isVerified ? '/dashboard.html' : '/pairing.html'
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    
    // Log login error
    await database.logLoginAttempt(
      req.body.username || 'unknown',
      req.ip,
      false,
      'server_error',
      error.message
    );
    
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat login. Silakan coba lagi nanti.' 
    });
  }
});

// Check session status
router.get('/session', sessionLimiter, async (req, res) => {
  try {
    if (!req.session.userId || !req.session.sessionId) {
      // Check for remember me cookie
      if (req.cookies && req.cookies.remember_me) {
        const user = await database.findUserByRememberToken(req.cookies.remember_me);
        
        if (user && user.isActive) {
          // Create new session
          const sessionId = Security.generateSessionId();
          await database.createSession(user.id, sessionId, {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            isVerified: user.isVerified
          });

          req.session.userId = user.id;
          req.session.sessionId = sessionId;
          req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            isVerified: user.isVerified,
            isAdmin: user.isAdmin || false,
            pairingStatus: user.pairingStatus || 'unpaired',
            needsPairing: !user.isVerified
          };

          return res.json({ 
            success: true, 
            isLoggedIn: true,
            data: {
              userId: user.id,
              username: user.username,
              email: user.email,
              isVerified: user.isVerified,
              pairingStatus: user.pairingStatus || 'unpaired',
              needsPairing: !user.isVerified
            }
          });
        }
      }
      
      return res.json({ 
        success: true, 
        isLoggedIn: false 
      });
    }

    // Validate existing session
    const session = await database.validateSession(req.session.sessionId);
    if (!session) {
      req.session.destroy();
      return res.json({ 
        success: true, 
        isLoggedIn: false 
      });
    }

    const user = await database.findUserById(req.session.userId);
    if (!user || !user.isActive) {
      req.session.destroy();
      return res.json({ 
        success: true, 
        isLoggedIn: false 
      });
    }

    res.json({ 
      success: true, 
      isLoggedIn: true,
      data: {
        userId: user.id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified,
        pairingStatus: user.pairingStatus || 'unpaired',
        needsPairing: !user.isVerified,
        isAdmin: user.isAdmin || false
      }
    });
  } catch (error) {
    console.error('Session check error:', error);
    res.json({ 
      success: false, 
      isLoggedIn: false,
      message: 'Error checking session'
    });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  try {
    // Invalidate session in database
    if (req.session.sessionId) {
      await database.invalidateSession(req.session.sessionId);
    }

    // Clear remember me token
    if (req.cookies && req.cookies.remember_me) {
      if (req.session.userId) {
        await database.clearRememberToken(req.session.userId);
      }
      res.clearCookie('remember_me');
    }

    // Destroy session
    req.session.destroy();

    res.json({ 
      success: true, 
      message: 'Logout berhasil',
      redirectTo: '/'
    });
  } catch (error) {
    console.error('Logout error:', error);
    
    // Force destroy session on error
    req.session.destroy();
    
    res.json({ 
      success: true, 
      message: 'Logout berhasil',
      redirectTo: '/'
    });
  }
});

// ===== PASSWORD RECOVERY ROUTES =====

// Forgot password
router.post('/forgot-password', rateLimitMiddleware(3, 60 * 60 * 1000), validateRequest(forgotPasswordSchema), async (req, res) => {
  try {
    const { email } = req.body;

    const user = await database.findUserByEmail(email);
    if (!user) {
      // Return success even if email doesn't exist (security best practice)
      return res.json({ 
        success: true, 
        message: 'Jika email terdaftar, instruksi reset password akan dikirim.'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

    // Save reset token to user
    await database.updateUser(user.id, {
      resetToken,
      resetTokenExpires: resetTokenExpires.toISOString()
    });

    // Send password reset email
    await emailService.sendPasswordResetEmail(user, resetToken);

    res.json({ 
      success: true, 
      message: 'Instruksi reset password telah dikirim ke email Anda. Link berlaku selama 1 jam.'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat memproses permintaan.' 
    });
  }
});

// Verify reset token
router.get('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const user = database.data.users.find(u => 
      u.resetToken === token && 
      u.resetTokenExpires &&
      new Date(u.resetTokenExpires) > new Date()
    );

    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token reset password tidak valid atau sudah kadaluarsa.' 
      });
    }

    res.json({ 
      success: true, 
      data: { 
        tokenValid: true,
        email: user.email 
      } 
    });
  } catch (error) {
    console.error('Reset token verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat memverifikasi token.' 
    });
  }
});

// Reset password
router.post('/reset-password', rateLimitMiddleware(3, 60 * 60 * 1000), validateRequest(resetPasswordSchema), async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Find user with valid reset token
    const user = database.data.users.find(u => 
      u.resetToken === token && 
      u.resetTokenExpires &&
      new Date(u.resetTokenExpires) > new Date()
    );

    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token reset password tidak valid atau sudah kadaluarsa.' 
      });
    }

    // Hash new password
    const hashedPassword = await Security.hashPassword(newPassword);

    // Update user password and clear reset token
    await database.updateUser(user.id, {
      password: hashedPassword.hash,
      salt: hashedPassword.salt,
      resetToken: null,
      resetTokenExpires: null,
      updatedAt: new Date().toISOString()
    });

    // Invalidate all user sessions
    await database.invalidateAllUserSessions(user.id);

    // Send password changed notification
    try {
      await emailService.sendEmail(
        user.email,
        'Password Berhasil Diubah',
        'password-changed',
        {
          name: user.username,
          timestamp: new Date().toLocaleString('id-ID')
        }
      );
    } catch (emailError) {
      console.error('Failed to send password changed email:', emailError);
    }

    res.json({ 
      success: true, 
      message: 'Password berhasil diubah. Silakan login dengan password baru.',
      redirectTo: '/login.html'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat reset password.' 
    });
  }
});

// ===== SYSTEM ROUTES =====

// Health check
router.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB`,
      heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)} MB`,
      heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`
    },
    database: {
      users: database.data.users?.length || 0,
      broadcasts: database.data.broadcasts?.length || 0,
      sessions: database.data.sessions?.filter(s => s.isValid)?.length || 0
    }
  };

  res.json(health);
});

// System information (public, limited info)
router.get('/system/info', (req, res) => {
  const info = {
    appName: process.env.APP_NAME || 'WhatsApp Broadcast Bot',
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    platform: process.platform,
    uptime: process.uptime(),
    serverTime: new Date().toISOString()
  };

  res.json({ success: true, data: info });
});

// ===== STATIC PAGE ROUTES =====

// Serve static pages with authentication check
const staticPages = {
  '/dashboard.html': { requiresAuth: true, requiresVerification: true },
  '/pairing.html': { requiresAuth: true, requiresVerification: false },
  '/broadcast.html': { requiresAuth: true, requiresVerification: true },
  '/contacts.html': { requiresAuth: true, requiresVerification: true },
  '/profile.html': { requiresAuth: true, requiresVerification: false },
  '/login.html': { requiresAuth: false },
  '/register.html': { requiresAuth: false },
  '/forgot-password.html': { requiresAuth: false },
  '/reset-password.html': { requiresAuth: false },
  '/terms.html': { requiresAuth: false },
  '/privacy.html': { requiresAuth: false },
  '/features.html': { requiresAuth: false },
  '/pricing.html': { requiresAuth: false }
};

// Dynamic static page routing
Object.keys(staticPages).forEach(pagePath => {
  router.get(pagePath, async (req, res, next) => {
    try {
      const pageConfig = staticPages[pagePath];
      
      // Check authentication requirements
      if (pageConfig.requiresAuth) {
        if (!req.session.userId || !req.session.sessionId) {
          return res.redirect('/login.html');
        }

        // Validate session
        const session = await database.validateSession(req.session.sessionId);
        if (!session) {
          req.session.destroy();
          return res.redirect('/login.html');
        }

        // Get user data
        const user = await database.findUserById(req.session.userId);
        if (!user || !user.isActive) {
          req.session.destroy();
          return res.redirect('/login.html');
        }

        // Check verification requirement
        if (pageConfig.requiresVerification && !user.isVerified) {
          return res.redirect('/pairing.html');
        }

        // Update session activity
        await database.updateSessionActivity(req.session.sessionId);
      }

      // Send the static file
      res.sendFile(path.join(__dirname, '../public', pagePath), err => {
        if (err) {
          if (err.code === 'ENOENT') {
            return res.status(404).send('Halaman tidak ditemukan');
          }
          next(err);
        }
      });
    } catch (error) {
      console.error(`Error serving ${pagePath}:`, error);
      res.status(500).send('Terjadi kesalahan server');
    }
  });
});

// ===== ERROR PAGES =====

// 404 page
router.use((req, res) => {
  if (req.accepts('html')) {
    res.status(404).sendFile(path.join(__dirname, '../public/404.html'));
  } else if (req.accepts('json')) {
    res.status(404).json({ 
      success: false, 
      message: 'Halaman tidak ditemukan',
      path: req.path 
    });
  } else {
    res.status(404).type('txt').send('404 Not Found');
  }
});

module.exports = router;
