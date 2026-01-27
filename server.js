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

// Import routers
const indexRouter = require('./routes/index');
const apiRouter = require('./routes/api');
const authRouter = require('./routes/auth');

// Import middleware
const { authenticate, requireVerification } = require('./middleware/auth');

// Import utils
const database = require('./utils/database');
const Security = require('./utils/security');
const { sendVerificationEmail, sendWelcomeEmail, sendPasswordResetEmail } = require('./utils/emailService');

const app = express();
const PORT = process.env.PORT || 8000;

// ===== EMAIL CONFIGURATION =====
const emailConfig = {
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'teguhmarwin99@gmail.com',
        pass: process.env.EMAIL_PASS || 'xqge rise pjpg oeei'
    }
};

// Create email transporter
const emailTransporter = nodemailer.createTransport({
    service: emailConfig.service,
    auth: emailConfig.auth
});

// Test email connection
emailTransporter.verify((error, success) => {
    if (error) {
        console.log('❌ Email server connection error:', error);
    } else {
        console.log('✅ Email server is ready to send messages');
    }
});

// ===== SECURITY MIDDLEWARE =====
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
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
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 auth requests per windowMs
    message: { 
        success: false, 
        message: 'Terlalu banyak percobaan login, coba lagi nanti' 
    },
    skipSuccessfulRequests: true
});

// ===== SESSION CONFIGURATION =====
const sessionConfig = {
    store: new FileStore({
        path: './sessions',
        ttl: 86400, // 24 jam
        retries: 3,
        secret: process.env.SESSION_SECRET || 'your-session-secret'
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
    name: 'whatsapp_broadcast.sid'
};

// Use secure cookies in production
if (app.get('env') === 'production') {
    app.set('trust proxy', 1);
    sessionConfig.cookie.secure = true;
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
    if (req.path.startsWith('/api/') && req.method === 'POST') {
        // Skip CSRF for API endpoints that might be called from mobile apps
        // In production, use proper authentication tokens instead
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
app.use(express.json({ limit: '10mb' }));
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
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
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
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    
    // Content Security Policy report only in development
    if (process.env.NODE_ENV === 'development') {
        res.setHeader('Content-Security-Policy-Report-Only', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';");
    }
    
    next();
});

// ===== CSRF TOKEN FOR VIEWS =====
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken ? req.csrfToken() : '';
    res.locals.user = req.session.user || null;
    res.locals.isAuthenticated = !!req.session.userId;
    res.locals.isVerified = req.session.user ? req.session.user.isVerified : false;
    next();
});

// ===== ROUTES =====

// Apply rate limiting to auth routes
app.use('/auth', authLimiter);

// Auth routes (login, register, verification)
app.use('/auth', authRouter);

// Index routes
app.use('/', indexRouter);

// API routes (protected)
app.use('/api', apiLimiter, authenticate, requireVerification, apiRouter);

// ===== ERROR HANDLERS =====

// 404 Handler
app.use((req, res, next) => {
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
        console.error('CSRF Token Error:', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path,
            method: req.method
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
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    .container { max-width: 500px; margin: 0 auto; }
                    .error { color: #dc3545; font-size: 24px; margin-bottom: 20px; }
                    .message { margin-bottom: 30px; }
                    button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error">⚠️ Token Tidak Valid</div>
                    <div class="message">
                        Sesi Anda telah kadaluarsa atau token tidak valid.<br>
                        Silakan refresh halaman dan coba lagi.
                    </div>
                    <button onclick="window.location.reload()">Refresh Halaman</button>
                </div>
            </body>
            </html>
        `);
    }
    next(err);
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('Server Error:', {
        error: err.message,
        stack: err.stack,
        ip: req.ip,
        url: req.originalUrl,
        method: req.method,
        userId: req.session.userId
    });
    
    // Log to file in production
    if (process.env.NODE_ENV === 'production') {
        const fs = require('fs');
        const logEntry = `${new Date().toISOString()} - ${err.message}\n${err.stack}\n\n`;
        fs.appendFileSync('./logs/errors.log', logEntry);
    }
    
    const statusCode = err.statusCode || 500;
    const message = process.env.NODE_ENV === 'production' 
        ? 'Terjadi kesalahan internal server' 
        : err.message;
    
    if (req.accepts('html')) {
        res.status(statusCode).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error ${statusCode}</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    .container { max-width: 500px; margin: 0 auto; }
                    .error-code { font-size: 72px; color: #dc3545; margin-bottom: 20px; }
                    .error-message { margin-bottom: 30px; }
                    .actions { display: flex; gap: 10px; justify-content: center; }
                    button { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
                    .primary { background: #007bff; color: white; }
                    .secondary { background: #6c757d; color: white; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error-code">${statusCode}</div>
                    <div class="error-message">${message}</div>
                    <div class="actions">
                        <button class="primary" onclick="window.history.back()">Kembali</button>
                        <button class="secondary" onclick="window.location.href='/'">Beranda</button>
                    </div>
                </div>
            </body>
            </html>
        `);
    } else if (req.accepts('json')) {
        res.status(statusCode).json({ 
            success: false, 
            message: message,
            ...(process.env.NODE_ENV === 'development' && { error: err.message, stack: err.stack })
        });
    } else {
        res.status(statusCode).type('txt').send(`Error ${statusCode}: ${message}`);
    }
});

// ===== DATABASE INITIALIZATION =====
async function initializeDatabase() {
    try {
        await database.init();
        console.log('✅ Database initialized successfully');
        
        // Create default admin user if not exists
        const adminExists = await database.findUser('admin');
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('Admin123!', 12);
            const adminUser = {
                id: 'admin_' + Date.now(),
                username: 'admin',
                email: 'admin@whatsbroadcast.com',
                password: hashedPassword,
                isVerified: true,
                isAdmin: true,
                isActive: true,
                createdAt: new Date().toISOString(),
                lastLogin: null,
                verificationToken: null,
                verificationExpires: null
            };
            
            database.data.users.push(adminUser);
            await database.save();
            console.log('👑 Admin user created (username: admin, password: Admin123!)');
        }
    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        process.exit(1);
    }
}

// ===== GRACEFUL SHUTDOWN =====
function gracefulShutdown(signal) {
    console.log(`\n${signal} received. Starting graceful shutdown...`);
    
    // Close server
    server.close(() => {
        console.log('✅ HTTP server closed');
        
        // Close database connections
        database.close && database.close();
        console.log('✅ Database connections closed');
        
        // Exit process
        process.exit(0);
    });
    
    // Force shutdown after 10 seconds
    setTimeout(() => {
        console.error('❌ Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 10000);
}

// ===== START SERVER =====
const server = app.listen(PORT, async () => {
    console.log(`
    🚀 WhatsApp Broadcast Bot Server
    =================================
    ✅ Server is running on port ${PORT}
    ✅ Environment: ${process.env.NODE_ENV || 'development'}
    ✅ Session Secret: ${process.env.SESSION_SECRET ? 'Set' : 'Not set (using default)'}
    ✅ Email Service: ${emailConfig.auth.user ? 'Configured' : 'Not configured'}
    =================================
    `);
    
    // Initialize database
    await initializeDatabase();
    
    // Log startup info
    console.log('\n📊 Server Information:');
    console.log(`   Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
    console.log(`   Node Version: ${process.version}`);
    console.log(`   Platform: ${process.platform} ${process.arch}`);
    
    // Log routes
    console.log('\n🛣️  Available Routes:');
    console.log('   GET  /                 - Landing page');
    console.log('   GET  /login.html       - Login page');
    console.log('   GET  /register.html    - Registration page');
    console.log('   GET  /dashboard.html   - Dashboard (requires auth)');
    console.log('   GET  /profile.html     - Profile (requires auth)');
    console.log('   GET  /work.html        - Broadcast (requires auth)');
    console.log('   POST /auth/register    - Register user');
    console.log('   POST /auth/login       - Login user');
    console.log('   POST /auth/verify      - Verify email');
    console.log('   POST /auth/resend      - Resend verification');
    console.log('   POST /auth/logout      - Logout user');
    console.log('   POST /api/*            - Protected API endpoints');
    console.log('\n🔒 Security Features:');
    console.log('   ✓ Rate limiting');
    console.log('   ✓ CSRF protection');
    console.log('   ✓ Helmet security headers');
    console.log('   ✓ Secure session management');
    console.log('   ✓ Email verification system');
    console.log('   ✓ Password hashing (bcrypt)');
    console.log('   ✓ Input sanitization');
    console.log('\n📧 Email System:');
    console.log(`   Service: ${emailConfig.service}`);
    console.log(`   From: ${emailConfig.auth.user}`);
    console.log(`   Status: ${emailTransporter ? 'Ready' : 'Not ready'}`);
});

// Handle server errors
server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
        console.log('💡 Try these solutions:');
        console.log('   1. Use a different port: PORT=3001 npm start');
        console.log('   2. Kill the process using the port:');
        console.log(`      On Linux/Mac: lsof -i :${PORT} | grep LISTEN | awk '{print $2}' | xargs kill -9`);
        console.log(`      On Windows: netstat -ano | findstr :${PORT}`);
        process.exit(1);
    } else {
        console.error('❌ Server error:', error);
        process.exit(1);
    }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    
    // Log to file
    const fs = require('fs').promises;
    const logEntry = `${new Date().toISOString()} - Uncaught Exception: ${error.message}\n${error.stack}\n\n`;
    
    fs.appendFile('./logs/crashes.log', logEntry).catch(console.error);
    
    // Don't exit in development to allow for debugging
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    
    // Log to file
    const fs = require('fs').promises;
    const logEntry = `${new Date().toISOString()} - Unhandled Rejection: ${reason}\n`;
    
    fs.appendFile('./logs/crashes.log', logEntry).catch(console.error);
});

// Graceful shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
