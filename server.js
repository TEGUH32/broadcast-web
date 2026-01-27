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
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cors = require('cors');
const compression = require('compression');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const winston = require('winston');
const fs = require('fs').promises;
const { promisify } = require('util');

// Import routers
const indexRouter = require('./routes/index');
const apiRouter = require('./routes/api');
const authRouter = require('./routes/auth');
const broadcastRouter = require('./routes/broadcast');
const pairingRouter = require('./routes/pairing');
const adminRouter = require('./routes/admin');

// Import middleware
const { 
  authenticate, 
  requireVerification,
  adminOnly,
  rateLimitMiddleware,
  validateRequest 
} = require('./middleware/auth');

// Import utils
const database = require('./utils/database');
const Security = require('./utils/security');
const { emailService } = require('./utils/email');

const app = express();
const PORT = process.env.PORT || 8000;

// ===== LOGGING CONFIGURATION =====
const logDir = path.join(__dirname, 'logs');

// Ensure log directory exists
(async () => {
  try {
    await fs.mkdir(logDir, { recursive: true });
  } catch (error) {
    console.error('Error creating log directory:', error);
  }
})();

const loggerConfig = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'whatsapp-broadcast-bot' },
  transports: [
    // Write all logs with level 'error' and below to error.log
    new winston.transports.File({ 
      filename: path.join(logDir, 'error.log'), 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    // Write all logs with level 'info' and below to combined.log
    new winston.transports.File({ 
      filename: path.join(logDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  ]
});

// If we're not in production, log to console as well
if (process.env.NODE_ENV !== 'production') {
  loggerConfig.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// ===== EMAIL CONFIGURATION =====
const emailConfig = {
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER || 'teguhmarwin99@gmail.com',
    pass: process.env.SMTP_PASS || 'xqge rise pjpg oeei'
  },
  tls: {
    rejectUnauthorized: false
  }
};

// Create email transporter
const emailTransporter = nodemailer.createTransport(emailConfig);

// Test email connection
emailTransporter.verify((error, success) => {
  if (error) {
    loggerConfig.error('❌ Email server connection error:', error);
  } else {
    loggerConfig.info('✅ Email server is ready to send messages');
  }
});

// ===== UPLOAD CONFIGURATION =====
const uploadDir = path.join(__dirname, 'uploads');

// Ensure upload directory exists
(async () => {
  try {
    await fs.mkdir(uploadDir, { recursive: true });
  } catch (error) {
    loggerConfig.error('Error creating upload directory:', error);
  }
})();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  // Accept images and PDFs
  const allowedTypes = /jpeg|jpg|png|gif|pdf/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Error: File type not supported!'));
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  },
  fileFilter: fileFilter
});

// ===== SECURITY MIDDLEWARE =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      workerSrc: ["'self'", "blob:"]
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ===== COMPRESSION =====
app.use(compression({
  level: 6,
  threshold: 100 * 1024 // Only compress responses larger than 100KB
}));

// ===== CORS CONFIGURATION =====
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.APP_URL, 'https://yourdomain.com']
    : ['http://localhost:3000', 'http://localhost:8000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With']
}));

// ===== RATE LIMITING =====
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { 
    success: false, 
    message: 'Terlalu banyak permintaan dari IP Anda, coba lagi nanti' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.ip;
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 auth requests per windowMs
  message: { 
    success: false, 
    message: 'Terlalu banyak percobaan login, coba lagi nanti' 
  },
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.body.username || req.body.email || req.ip;
  }
});

const strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 requests per hour
  message: { 
    success: false, 
    message: 'Terlalu banyak permintaan kritis, coba lagi nanti' 
  },
  keyGenerator: (req) => req.ip
});

// ===== SESSION CONFIGURATION =====
const sessionConfig = {
  store: new FileStore({
    path: './sessions',
    ttl: 86400, // 24 jam
    retries: 3,
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    logFn: (...args) => loggerConfig.debug('Session store:', ...args)
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 jam
    sameSite: 'strict',
    domain: process.env.COOKIE_DOMAIN || 'localhost'
  },
  name: 'whatsapp_broadcast.sid',
  genid: function(req) {
    return uuidv4();
  }
};

// Use secure cookies in production
if (app.get('env') === 'production') {
  app.set('trust proxy', 1);
  sessionConfig.cookie.secure = true;
  sessionConfig.cookie.sameSite = 'none';
}

app.use(session(sessionConfig));

// ===== CSRF PROTECTION =====
const csrfProtection = csrf({ 
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF to all routes except API endpoints that need to be accessed from mobile apps
app.use((req, res, next) => {
  if (req.path.startsWith('/api/v1/') || req.path === '/api/webhook') {
    // Skip CSRF for API v1 endpoints and webhooks
    next();
  } else {
    csrfProtection(req, res, next);
  }
});

// ===== SERVER CONFIGURATION =====
app.set('json spaces', 2);
app.set('view engine', 'html');
app.set('views', path.join(__dirname, 'public'));

// ===== LOGGING =====
app.use(logger(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ===== BODY PARSING =====
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb',
  parameterLimit: 10000 
}));

// ===== COOKIE PARSER =====
app.use(cookieParser());

// ===== STATIC FILES =====
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    } else if (filePath.match(/\.(js|css)$/)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 year
    } else if (filePath.match(/\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/)) {
      res.setHeader('Cache-Control', 'public, max-age=604800'); // 1 week
    }
  }
}));

// Serve uploads
app.use('/uploads', express.static(uploadDir, {
  maxAge: '7d',
  setHeaders: (res, filePath) => {
    // Only allow specific file types
    if (filePath.match(/\.(png|jpg|jpeg|gif|pdf)$/)) {
      res.setHeader('Content-Disposition', 'inline');
    } else {
      res.setHeader('Content-Disposition', 'attachment');
    }
  }
}));

// ===== SECURITY HEADERS =====
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Enable XSS filter
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions policy
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  
  // Cross-origin opener policy
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  
  // Cross-origin resource policy
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  
  // Cross-origin embedder policy
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  
  next();
});

// ===== REQUEST LOGGING MIDDLEWARE =====
app.use((req, res, next) => {
  const start = Date.now();
  
  // Log request
  loggerConfig.info('Request', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.session?.userId
  });
  
  // Capture response
  const originalSend = res.send;
  res.send = function(body) {
    const duration = Date.now() - start;
    
    loggerConfig.info('Response', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userId: req.session?.userId
    });
    
    // Log errors
    if (res.statusCode >= 400) {
      loggerConfig.error('Error Response', {
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        body: typeof body === 'string' ? body.substring(0, 500) : body,
        userId: req.session?.userId
      });
    }
    
    return originalSend.call(this, body);
  };
  
  next();
});

// ===== CSRF TOKEN FOR VIEWS =====
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken ? req.csrfToken() : '';
  res.locals.user = req.session.user || null;
  res.locals.isAuthenticated = !!req.session.userId;
  res.locals.isVerified = req.session.user ? req.session.user.isVerified : false;
  res.locals.isAdmin = req.session.user ? req.session.user.isAdmin : false;
  res.locals.appName = process.env.APP_NAME || 'WhatsApp Broadcast Bot';
  res.locals.appUrl = process.env.APP_URL || `http://localhost:${PORT}`;
  res.locals.currentYear = new Date().getFullYear();
  next();
});

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: database.data ? 'connected' : 'disconnected',
    email: emailTransporter ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV || 'development'
  };
  
  res.json(health);
});

// ===== SYSTEM INFO =====
app.get('/system/info', authenticate, adminOnly, (req, res) => {
  const systemInfo = {
    nodeVersion: process.version,
    platform: process.platform,
    architecture: process.arch,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    cpuUsage: process.cpuUsage(),
    env: process.env.NODE_ENV,
    appVersion: process.env.npm_package_version || '1.0.0'
  };
  
  res.json({
    success: true,
    data: systemInfo
  });
});

// ===== ROUTES =====

// Apply rate limiting
app.use('/auth', authLimiter);
app.use('/api/auth', authLimiter);
app.use('/api/pairing', strictLimiter);

// Public routes
app.use('/auth', authRouter);
app.use('/', indexRouter);

// Protected routes
app.use('/api/broadcast', apiLimiter, authenticate, requireVerification, broadcastRouter);
app.use('/api/pairing', authenticate, pairingRouter);
app.use('/api/admin', apiLimiter, authenticate, adminOnly, adminRouter);
app.use('/api', apiLimiter, authenticate, requireVerification, apiRouter);

// ===== FILE UPLOAD ENDPOINT =====
app.post('/api/upload', authenticate, requireVerification, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'Tidak ada file yang diupload'
      });
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (!allowedTypes.includes(req.file.mimetype)) {
      await fs.unlink(req.file.path).catch(() => {});
      return res.status(400).json({
        success: false,
        message: 'Tipe file tidak didukung'
      });
    }

    // Log upload
    await database.logRequest({
      method: 'POST',
      url: '/api/upload',
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user.id,
      metadata: {
        filename: req.file.filename,
        originalname: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
      }
    });

    res.json({
      success: true,
      message: 'File berhasil diupload',
      file: {
        filename: req.file.filename,
        originalname: req.file.originalname,
        path: `/uploads/${req.file.filename}`,
        size: req.file.size,
        mimetype: req.file.mimetype
      }
    });
  } catch (error) {
    loggerConfig.error('Upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan saat upload file'
    });
  }
});

// ===== ERROR HANDLERS =====

// 404 Handler
app.use((req, res, next) => {
  loggerConfig.warn('404 Not Found', {
    ip: req.ip,
    url: req.originalUrl,
    method: req.method,
    userAgent: req.get('User-Agent')
  });

  if (req.accepts('html')) {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  } else if (req.accepts('json')) {
    res.status(404).json({ 
      success: false, 
      message: 'Endpoint tidak ditemukan',
      path: req.path
    });
  } else {
    res.status(404).type('txt').send('404 Not Found');
  }
});

// CSRF Error Handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    loggerConfig.error('CSRF Token Error:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      userId: req.session?.userId
    });
    
    if (req.accepts('json')) {
      return res.status(403).json({ 
        success: false, 
        message: 'Token CSRF tidak valid. Silakan refresh halaman.' 
      });
    }
    
    return res.status(403).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Token Tidak Valid</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; 
                align-items: center; justify-content: center; }
          .container { background: white; padding: 40px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
                      max-width: 500px; width: 90%; text-align: center; }
          .error-icon { font-size: 80px; color: #ff4757; margin-bottom: 20px; }
          h1 { color: #2d3436; margin-bottom: 15px; font-size: 28px; }
          p { color: #636e72; margin-bottom: 30px; line-height: 1.6; }
          .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; 
                padding: 15px 40px; font-size: 16px; border-radius: 50px; cursor: pointer; 
                text-decoration: none; display: inline-block; transition: transform 0.3s, box-shadow 0.3s; }
          .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4); }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="error-icon">⚠️</div>
          <h1>Session Expired</h1>
          <p>Your session has expired or the security token is invalid.<br>
             Please refresh the page and try again.</p>
          <button onclick="window.location.reload()" class="btn">Refresh Page</button>
        </div>
      </body>
      </html>
    `);
  }
  next(err);
});

// Multer Error Handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    loggerConfig.error('Multer Error:', err);
    
    let message = 'Terjadi kesalahan saat upload file';
    if (err.code === 'LIMIT_FILE_SIZE') {
      message = 'Ukuran file terlalu besar. Maksimal 5MB';
    } else if (err.code === 'LIMIT_FILE_COUNT') {
      message = 'Terlalu banyak file diupload';
    } else if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      message = 'Field file tidak sesuai';
    }
    
    return res.status(400).json({
      success: false,
      message: message
    });
  }
  next(err);
});

// Global Error Handler
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const isProduction = process.env.NODE_ENV === 'production';
  
  loggerConfig.error('Server Error:', {
    error: err.message,
    stack: err.stack,
    ip: req.ip,
    url: req.originalUrl,
    method: req.method,
    userId: req.session?.userId,
    body: req.body,
    query: req.query
  });
  
  // Send email alert for critical errors in production
  if (isProduction && statusCode >= 500) {
    emailService.sendAdminAlert(
      `Server Error ${statusCode}`,
      `Path: ${req.path}\nMethod: ${req.method}\nError: ${err.message}\nIP: ${req.ip}`,
      'error'
    ).catch(emailError => {
      loggerConfig.error('Failed to send error alert:', emailError);
    });
  }
  
  const response = {
    success: false,
    message: isProduction ? 'Terjadi kesalahan internal server' : err.message
  };
  
  if (!isProduction && err.stack) {
    response.stack = err.stack;
  }
  
  if (req.accepts('html')) {
    res.status(statusCode).render('error', {
      errorCode: statusCode,
      errorMessage: response.message,
      stack: isProduction ? null : err.stack
    });
  } else if (req.accepts('json')) {
    res.status(statusCode).json(response);
  } else {
    res.status(statusCode).type('txt').send(`Error ${statusCode}: ${response.message}`);
  }
});

// ===== DATABASE INITIALIZATION =====
async function initializeDatabase() {
  try {
    await database.init();
    loggerConfig.info('✅ Database initialized successfully');
    
    // Create default admin user if not exists
    const adminExists = await database.findUser('admin');
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin123!', 12);
      const adminUser = {
        id: 'admin_' + Date.now(),
        username: 'admin',
        email: 'admin@whatsbroadcast.com',
        password: hashedPassword,
        role: 'admin',
        isVerified: true,
        isAdmin: true,
        isActive: true,
        pairingStatus: 'paired',
        rememberToken: crypto.randomBytes(32).toString('hex'),
        rememberExpires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        lastLogin: null,
        profile: {
          fullName: 'Administrator',
          avatar: null,
          settings: {}
        }
      };
      
      database.data.users.push(adminUser);
      await database.save();
      
      loggerConfig.info('👑 Admin user created (username: admin, password: Admin123!)');
      
      // Send welcome email to admin
      try {
        await emailService.sendWelcomeEmail(adminUser);
        loggerConfig.info('📧 Welcome email sent to admin');
      } catch (emailError) {
        loggerConfig.error('Failed to send welcome email to admin:', emailError);
      }
    }
    
    // Create uploads directory if not exists
    try {
      await fs.access(uploadDir);
    } catch {
      await fs.mkdir(uploadDir, { recursive: true });
      loggerConfig.info('📁 Uploads directory created');
    }
    
    // Create sessions directory if not exists
    try {
      await fs.access('./sessions');
    } catch {
      await fs.mkdir('./sessions', { recursive: true });
      loggerConfig.info('📁 Sessions directory created');
    }
  } catch (error) {
    loggerConfig.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

// ===== GRACEFUL SHUTDOWN =====
async function gracefulShutdown(signal) {
  loggerConfig.info(`${signal} received. Starting graceful shutdown...`);
  
  // Close server
  server.close(async () => {
    loggerConfig.info('✅ HTTP server closed');
    
    try {
      // Save database
      await database.save();
      loggerConfig.info('✅ Database saved');
      
      // Close email transporter
      if (emailTransporter) {
        emailTransporter.close();
        loggerConfig.info('✅ Email transporter closed');
      }
      
      // Exit process
      process.exit(0);
    } catch (error) {
      loggerConfig.error('Error during shutdown:', error);
      process.exit(1);
    }
  });
  
  // Force shutdown after 30 seconds
  setTimeout(() => {
    loggerConfig.error('❌ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
}

// ===== START SERVER =====
const server = app.listen(PORT, '0.0.0.0', async () => {
  const networkInterfaces = require('os').networkInterfaces();
  let localIp = 'localhost';
  
  Object.keys(networkInterfaces).forEach((interfaceName) => {
    networkInterfaces[interfaceName].forEach((interface) => {
      if (interface.family === 'IPv4' && !interface.internal) {
        localIp = interface.address;
      }
    });
  });
  
  console.log(`
    🚀 WhatsApp Broadcast Bot Server
    =================================
    ✅ Server is running!
    🔗 Local: http://localhost:${PORT}
    🌐 Network: http://${localIp}:${PORT}
    📁 Environment: ${process.env.NODE_ENV || 'development'}
    📅 Started: ${new Date().toLocaleString()}
    =================================
    `);
  
  // Initialize database
  await initializeDatabase();
  
  // Log startup info
  loggerConfig.info('Server Information:', {
    memoryUsage: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`,
    nodeVersion: process.version,
    platform: `${process.platform} ${process.arch}`,
    pid: process.pid,
    port: PORT
  });
  
  // Log system status
  loggerConfig.info('System Status:', {
    databaseUsers: database.data.users.length,
    databaseBroadcasts: database.data.broadcasts.length,
    emailService: emailTransporter ? 'Connected' : 'Not connected',
    uploadDirectory: uploadDir,
    logDirectory: logDir
  });
});

// Handle server errors
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    loggerConfig.error(`Port ${PORT} is already in use`);
    
    console.log('\n💡 Try these solutions:');
    console.log(`   1. Use a different port: PORT=3001 npm start`);
    console.log(`   2. Kill the process using the port:`);
    console.log(`      On Linux/Mac: lsof -i :${PORT} | grep LISTEN | awk '{print $2}' | xargs kill -9`);
    console.log(`      On Windows: netstat -ano | findstr :${PORT}`);
    
    process.exit(1);
  } else {
    loggerConfig.error('Server error:', error);
    process.exit(1);
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  loggerConfig.error('❌ Uncaught Exception:', error);
  
  // Send emergency email alert
  if (process.env.NODE_ENV === 'production') {
    emailService.sendAdminAlert(
      'CRITICAL: Uncaught Exception',
      `Error: ${error.message}\nStack: ${error.stack}`,
      'critical'
    ).catch(() => {});
  }
  
  // Don't exit in development to allow for debugging
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  loggerConfig.error('❌ Unhandled Rejection:', {
    reason: reason,
    promise: promise
  });
});

// Graceful shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Memory leak detection (in development)
if (process.env.NODE_ENV === 'development') {
  const memoryLeakDetection = setInterval(() => {
    const memoryUsage = process.memoryUsage();
    if (memoryUsage.heapUsed > 500 * 1024 * 1024) { // 500MB
      loggerConfig.warn('⚠️ Possible memory leak detected:', memoryUsage);
    }
  }, 60000); // Check every minute
  
  // Clean up on shutdown
  process.on('exit', () => {
    clearInterval(memoryLeakDetection);
  });
}

module.exports = { app, server, database, emailTransporter, loggerConfig };
