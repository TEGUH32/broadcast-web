const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Session configuration for Vercel
app.use(session({
  store: new MemoryStore({
    checkPeriod: 86400000 // Cleanup expired sessions every 24h
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key-here',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Middleware
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Simple in-memory database for demo
const users = [];

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if user exists
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Save user
    users.push({
      id: Date.now(),
      username,
      password: hashedPassword,
      createdAt: new Date()
    });
    
    res.json({ success: true, message: 'User registered' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;
    
    res.json({ success: true, message: 'Login successful' });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// QR Code endpoint
app.get('/api/qr', (req, res) => {
  // This would generate QR for WhatsApp Web
  res.json({ 
    qr: 'data:image/png;base64,placeholder',
    message: 'WhatsApp Web QR would be generated here'
  });
});

// Status endpoint
app.get('/api/status', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  res.json({
    status: 'online',
    user: req.session.username,
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Export for Vercel
module.exports = app;
