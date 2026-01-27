const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const rateLimit = require("express-rate-limit");
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const helmet = require('helmet');
const csrf = require('csurf');
const bcrypt = require('bcryptjs');

const indexRouter = require('./routes/index');
const apiRouter = require('./routes/api');
const { authenticate } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 8000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Terlalu banyak permintaan, coba lagi nanti' }
});

app.use(limiter);

// Session configuration
app.use(session({
  store: new FileStore({
    path: './sessions',
    ttl: 86400, // 24 jam
    retries: 3
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 jam
    sameSite: 'strict'
  }
}));

// CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

app.set('json spaces', 2);
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Serve static files
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

// CSRF token untuk semua views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Routes
app.use('/', indexRouter);
app.use('/api', authenticate, apiRouter);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint tidak ditemukan' 
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ 
      success: false, 
      message: 'Token CSRF tidak valid' 
    });
  }
  
  res.status(500).json({ 
    success: false, 
    message: 'Terjadi kesalahan internal server' 
  });
});

app.listen(PORT, () => {
  console.log(`✅ Server berjalan di port ${PORT}`);
});
