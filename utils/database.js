// Dengan database yang diperbarui, middleware autentikasi akan berfungsi dengan semua fitur:
const {
  authenticate,
  requirePairing,
  apiKeyAuth,
  rateLimitMiddleware
} = require('./middlewares/auth.js');

// Route dengan semua fitur
app.post('/login', 
  rateLimitMiddleware(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  async (req, res) => {
    const { username, password, rememberMe } = req.body;
    
    // Log login attempt
    await database.logLoginAttempt(username, req.ip, false, 'attempt');
    
    const user = await database.findUser(username);
    if (!user) {
      await database.logLoginAttempt(username, req.ip, false, 'user_not_found');
      return res.status(401).json({ error: 'User tidak ditemukan' });
    }
    
    const isValid = await database.verifyPassword(user, password);
    if (!isValid) {
      await database.logLoginAttempt(username, req.ip, false, 'wrong_password');
      return res.status(401).json({ error: 'Password salah' });
    }
    
    // Create session
    const sessionId = crypto.randomBytes(32).toString('hex');
    await database.createSession(user.id, sessionId, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      isVerified: user.isVerified
    });
    
    // Set remember me cookie if requested
    if (rememberMe) {
      res.cookie('remember_me', user.rememberToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        sameSite: 'strict'
      });
    }
    
    // Update last login
    await database.updateUserLastLogin(user.id);
    await database.logLoginAttempt(username, req.ip, true, 'success');
    
    res.json({ 
      success: true, 
      user: { 
        id: user.id, 
        username: user.username,
        isVerified: user.isVerified 
      } 
    });
  }
);
