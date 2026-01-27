const express = require('express');
const router = express.Router();
const database = require('../utils/database');
const Security = require('../utils/security');

// Home page
router.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard.html');
  }
  res.redirect('/login.html');
});

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // Validation
    if (!username || !password || !email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Semua field harus diisi' 
      });
    }

    if (!Security.validateEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Format email tidak valid' 
      });
    }

    if (!Security.validatePassword(password)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password minimal 8 karakter dengan 1 huruf besar dan 1 angka' 
      });
    }

    // Create user
    const user = await database.createUser(
      Security.sanitizeInput(username),
      password,
      Security.sanitizeInput(email)
    );

    // Create session
    const sessionId = Security.generateSessionId();
    await database.createSession(user.id, sessionId);

    req.session.userId = user.id;
    req.session.sessionId = sessionId;
    req.session.username = user.username;

    res.json({ 
      success: true, 
      message: 'Registrasi berhasil!',
      data: { 
        userId: user.id,
        needsPairing: true
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username dan password harus diisi' 
      });
    }

    // Rate limiting check
    const loginAttempts = database.data.loginAttempts || [];
    const attempts = Security.checkRateLimit(req.ip, loginAttempts);
    
    if (attempts >= 5) {
      return res.status(429).json({ 
        success: false, 
        message: 'Terlalu banyak percobaan login. Coba lagi nanti.' 
      });
    }

    // Find user
    const user = await database.findUser(Security.sanitizeInput(username));
    if (!user) {
      database.data.loginAttempts.push({ ip: req.ip, timestamp: Date.now() });
      await database.save();
      
      return res.status(401).json({ 
        success: false, 
        message: 'Username atau password salah' 
      });
    }

    // Verify password
    const isValid = await database.verifyPassword(user, password);
    if (!isValid) {
      database.data.loginAttempts.push({ ip: req.ip, timestamp: Date.now() });
      await database.save();
      
      return res.status(401).json({ 
        success: false, 
        message: 'Username atau password salah' 
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(403).json({ 
        success: false, 
        message: 'Akun dinonaktifkan' 
      });
    }

    // Create session
    const sessionId = Security.generateSessionId();
    await database.createSession(user.id, sessionId);

    // Update last login
    await database.updateUser(user.id, { lastLogin: new Date().toISOString() });

    req.session.userId = user.id;
    req.session.sessionId = sessionId;
    req.session.username = user.username;

    // Clear failed attempts
    database.data.loginAttempts = database.data.loginAttempts.filter(
      attempt => attempt.ip !== req.ip
    );
    await database.save();

    res.json({ 
      success: true, 
      message: 'Login berhasil!',
      data: { 
        userId: user.id,
        isVerified: user.isVerified 
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Check session
router.get('/session', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.sessionId) {
      return res.json({ success: false, isLoggedIn: false });
    }

    const session = await database.validateSession(req.session.sessionId);
    if (!session) {
      req.session.destroy();
      return res.json({ success: false, isLoggedIn: false });
    }

    const user = await database.findUserById(req.session.userId);
    if (!user || !user.isActive) {
      req.session.destroy();
      return res.json({ success: false, isLoggedIn: false });
    }

    res.json({ 
      success: true, 
      isLoggedIn: true,
      data: {
        username: user.username,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    res.json({ success: false, isLoggedIn: false });
  }
});

module.exports = router;
