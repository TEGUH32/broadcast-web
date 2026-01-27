const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Import utils
const database = require('../utils/database');
const Security = require('../utils/security');
const emailService = require('../utils/emailService');

// ===== REGISTER USER =====
router.post('/register', async (req, res) => {
    try {
        const { username, email, password, fullName, phone, company, usageType } = req.body;

        console.log('Registration attempt:', { username, email, phone });

        // Validation
        if (!username || !email || !password || !phone) {
            return res.status(400).json({
                success: false,
                message: 'Semua field wajib diisi: username, email, password, nomor WhatsApp'
            });
        }

        // Validate username
        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({
                success: false,
                message: 'Username harus 3-20 karakter'
            });
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({
                success: false,
                message: 'Username hanya boleh berisi huruf, angka, dan underscore'
            });
        }

        // Validate email
        if (!Security.validateEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Format email tidak valid'
            });
        }

        // Validate password
        if (!Security.validatePassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password minimal 8 karakter dengan 1 huruf besar dan 1 angka'
            });
        }

        // Validate phone number
        if (!Security.validatePhoneNumber(phone)) {
            return res.status(400).json({
                success: false,
                message: 'Format nomor WhatsApp tidak valid. Gunakan format 628xxxx'
            });
        }

        // Check if user already exists
        const existingUser = await database.findUser(username);
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Username sudah terdaftar'
            });
        }

        // Check if email already exists
        const existingEmail = database.data.users.find(u => u.email === email);
        if (existingEmail) {
            return res.status(400).json({
                success: false,
                message: 'Email sudah terdaftar'
            });
        }

        // Check if phone already exists
        const existingPhone = database.data.users.find(u => u.phone === phone);
        if (existingPhone) {
            return res.status(400).json({
                success: false,
                message: 'Nomor WhatsApp sudah terdaftar'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generate verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Create user object
        const user = {
            id: 'user_' + Date.now(),
            username: Security.sanitizeInput(username),
            email: Security.sanitizeInput(email),
            password: hashedPassword,
            fullName: fullName ? Security.sanitizeInput(fullName) : '',
            phone: Security.sanitizeInput(phone),
            company: company ? Security.sanitizeInput(company) : '',
            usageType: usageType || 'personal',
            isVerified: false,
            isAdmin: false,
            isActive: true,
            verificationToken,
            verificationCode,
            verificationExpires: verificationExpires.toISOString(),
            verificationAttempts: 0,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            lastLogin: null,
            loginAttempts: 0,
            lastAttempt: null,
            resetPasswordToken: null,
            resetPasswordExpires: null
        };

        // Save user to database
        database.data.users.push(user);
        await database.save();

        // Send verification email
        try {
            await emailService.sendVerificationEmail(user, verificationCode);
            console.log('Verification email sent to:', user.email);
        } catch (emailError) {
            console.error('Failed to send verification email:', emailError);
            // Continue even if email fails - user can request resend
        }

        // Create session (but don't mark as logged in until verified)
        const sessionId = Security.generateSessionId();
        await database.createSession(user.id, sessionId, {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            isVerified: false
        });

        // Set session data
        req.session.userId = user.id;
        req.session.sessionId = sessionId;
        req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            isVerified: false,
            needsVerification: true
        };

        // Log registration
        await database.logActivity({
            userId: user.id,
            type: 'registration',
            description: 'User registered',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Registrasi berhasil! Silakan verifikasi email Anda.',
            data: {
                userId: user.id,
                email: user.email,
                needsVerification: true,
                verificationMethod: 'email'
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat registrasi'
        });
    }
});

// ===== VERIFY EMAIL =====
router.post('/verify', async (req, res) => {
    try {
        const { code } = req.body;
        const userId = req.session.userId;

        if (!userId) {
            return res.status(401).json({
                success: false,
                message: 'Sesi tidak valid'
            });
        }

        if (!code || code.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Kode verifikasi harus 6 digit'
            });
        }

        // Find user
        const user = await database.findUserById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User tidak ditemukan'
            });
        }

        // Check if already verified
        if (user.isVerified) {
            return res.json({
                success: true,
                message: 'Email sudah diverifikasi',
                data: { isVerified: true }
            });
        }

        // Check verification attempts
        if (user.verificationAttempts >= 5) {
            return res.status(429).json({
                success: false,
                message: 'Terlalu banyak percobaan verifikasi. Silakan request kode baru.'
            });
        }

        // Check if code is expired
        const now = new Date();
        const expiresAt = new Date(user.verificationExpires);
        
        if (now > expiresAt) {
            return res.status(400).json({
                success: false,
                message: 'Kode verifikasi telah kadaluarsa. Silakan request kode baru.'
            });
        }

        // Verify code
        if (user.verificationCode !== code) {
            // Increment attempts
            user.verificationAttempts = (user.verificationAttempts || 0) + 1;
            user.updatedAt = new Date().toISOString();
            await database.save();

            return res.status(400).json({
                success: false,
                message: `Kode verifikasi salah. Percobaan ke-${user.verificationAttempts} dari 5.`
            });
        }

        // Mark as verified
        user.isVerified = true;
        user.verificationToken = null;
        user.verificationCode = null;
        user.verificationExpires = null;
        user.verificationAttempts = 0;
        user.verifiedAt = new Date().toISOString();
        user.updatedAt = new Date().toISOString();

        // Update session
        const session = await database.validateSession(req.session.sessionId);
        if (session) {
            session.isVerified = true;
            session.lastActive = new Date().toISOString();
        }

        // Update user in database
        await database.save();

        // Update session data
        req.session.user.isVerified = true;
        req.session.user.needsVerification = false;

        // Send welcome email
        try {
            await emailService.sendWelcomeEmail(user);
            console.log('Welcome email sent to:', user.email);
        } catch (emailError) {
            console.error('Failed to send welcome email:', emailError);
        }

        // Log verification
        await database.logActivity({
            userId: user.id,
            type: 'verification',
            description: 'Email verified successfully',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Email berhasil diverifikasi!',
            data: {
                userId: user.id,
                username: user.username,
                email: user.email,
                isVerified: true,
                verifiedAt: user.verifiedAt
            }
        });

    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat verifikasi'
        });
    }
});

// ===== RESEND VERIFICATION =====
router.post('/resend-verification', async (req, res) => {
    try {
        const userId = req.session.userId;

        if (!userId) {
            return res.status(401).json({
                success: false,
                message: 'Sesi tidak valid'
            });
        }

        // Find user
        const user = await database.findUserById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User tidak ditemukan'
            });
        }

        // Check if already verified
        if (user.isVerified) {
            return res.json({
                success: true,
                message: 'Email sudah diverifikasi',
                data: { isVerified: true }
            });
        }

        // Check resend cooldown (prevent spam)
        const lastResend = user.lastResendAttempt ? new Date(user.lastResendAttempt) : null;
        const now = new Date();
        
        if (lastResend && (now - lastResend) < 60000) { // 1 minute cooldown
            const secondsLeft = Math.ceil((60000 - (now - lastResend)) / 1000);
            return res.status(429).json({
                success: false,
                message: `Silakan tunggu ${secondsLeft} detik sebelum request kode baru`
            });
        }

        // Generate new verification code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Update user
        user.verificationCode = verificationCode;
        user.verificationExpires = verificationExpires.toISOString();
        user.verificationAttempts = 0;
        user.lastResendAttempt = new Date().toISOString();
        user.updatedAt = new Date().toISOString();

        await database.save();

        // Send verification email
        try {
            await emailService.sendVerificationEmail(user, verificationCode);
            console.log('Verification email resent to:', user.email);
        } catch (emailError) {
            console.error('Failed to resend verification email:', emailError);
            return res.status(500).json({
                success: false,
                message: 'Gagal mengirim email verifikasi'
            });
        }

        // Log resend attempt
        await database.logActivity({
            userId: user.id,
            type: 'verification_resend',
            description: 'Verification code resent',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Kode verifikasi baru telah dikirim ke email Anda',
            data: {
                email: user.email,
                expiresIn: '10 menit'
            }
        });

    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat mengirim kode verifikasi'
        });
    }
});

// ===== LOGIN USER =====
router.post('/login', async (req, res) => {
    try {
        const { username, password, rememberMe } = req.body;

        // Validation
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
                message: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.'
            });
        }

        // Find user
        const user = await database.findUser(username);
        if (!user) {
            // Log failed attempt
            database.data.loginAttempts.push({ 
                ip: req.ip, 
                timestamp: Date.now(),
                username: username
            });
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
                message: 'Akun Anda dinonaktifkan'
            });
        }

        // Verify password
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            // Log failed attempt
            database.data.loginAttempts.push({ 
                ip: req.ip, 
                timestamp: Date.now(),
                username: username,
                userId: user.id
            });
            
            // Increment user's failed attempts
            user.loginAttempts = (user.loginAttempts || 0) + 1;
            user.lastAttempt = new Date().toISOString();
            
            // Lock account after 5 failed attempts
            if (user.loginAttempts >= 5) {
                user.isActive = false;
                user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 minutes
            }
            
            await database.save();

            return res.status(401).json({
                success: false,
                message: 'Username atau password salah'
            });
        }

        // Check if account is locked
        if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
            const minutesLeft = Math.ceil((new Date(user.lockedUntil) - new Date()) / (60 * 1000));
            return res.status(403).json({
                success: false,
                message: `Akun terkunci. Coba lagi dalam ${minutesLeft} menit.`
            });
        }

        // Reset failed attempts on successful login
        user.loginAttempts = 0;
        user.lastAttempt = null;
        user.lockedUntil = null;
        user.lastLogin = new Date().toISOString();
        await database.save();

        // Clear failed attempts for this IP
        database.data.loginAttempts = database.data.loginAttempts.filter(
            attempt => attempt.ip !== req.ip
        );
        await database.save();

        // Create session
        const sessionId = Security.generateSessionId();
        await database.createSession(user.id, sessionId, {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            isVerified: user.isVerified
        });

        // Set session data
        req.session.userId = user.id;
        req.session.sessionId = sessionId;
        req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            isVerified: user.isVerified,
            isAdmin: user.isAdmin || false,
            needsVerification: !user.isVerified
        };

        // Set remember me cookie
        if (rememberMe) {
            const rememberToken = crypto.randomBytes(32).toString('hex');
            const rememberExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
            
            user.rememberToken = rememberToken;
            user.rememberExpires = rememberExpires.toISOString();
            await database.save();

            res.cookie('remember_me', rememberToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 30 * 24 * 60 * 60 * 1000,
                sameSite: 'strict'
            });
        }

        // Log successful login
        await database.logActivity({
            userId: user.id,
            type: 'login',
            description: 'User logged in successfully',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: user.isVerified ? 'Login berhasil!' : 'Login berhasil! Silakan verifikasi email Anda.',
            data: {
                userId: user.id,
                username: user.username,
                isVerified: user.isVerified,
                needsVerification: !user.isVerified,
                redirectTo: user.isVerified ? '/dashboard.html' : '/verify.html'
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat login'
        });
    }
});

// ===== LOGOUT =====
router.post('/logout', async (req, res) => {
    try {
        if (req.session.sessionId) {
            // Invalidate session in database
            await database.invalidateSession(req.session.sessionId);
        }

        // Clear remember me token
        if (req.cookies.remember_me) {
            res.clearCookie('remember_me');
        }

        // Destroy session
        req.session.destroy();

        res.json({
            success: true,
            message: 'Logout berhasil'
        });

    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat logout'
        });
    }
});

// ===== CHECK VERIFICATION STATUS =====
router.get('/verification-status', async (req, res) => {
    try {
        const userId = req.session.userId;

        if (!userId) {
            return res.status(401).json({
                success: false,
                message: 'Sesi tidak valid'
            });
        }

        const user = await database.findUserById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User tidak ditemukan'
            });
        }

        res.json({
            success: true,
            data: {
                isVerified: user.isVerified,
                email: user.email,
                needsVerification: !user.isVerified,
                verifiedAt: user.verifiedAt,
                canResend: !user.lastResendAttempt || 
                    (new Date() - new Date(user.lastResendAttempt) > 60000)
            }
        });

    } catch (error) {
        console.error('Verification status error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan'
        });
    }
});

// ===== FORGOT PASSWORD =====
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email harus diisi'
            });
        }

        // Find user by email
        const user = database.data.users.find(u => u.email === email);
        if (!user) {
            // Return success even if user not found (security measure)
            return res.json({
                success: true,
                message: 'Jika email terdaftar, instruksi reset password akan dikirim'
            });
        }

        // Check if user can request reset (cooldown)
        const lastReset = user.lastPasswordReset ? new Date(user.lastPasswordReset) : null;
        const now = new Date();
        
        if (lastReset && (now - lastReset) < 15 * 60 * 1000) { // 15 minutes cooldown
            const minutesLeft = Math.ceil((15 * 60 * 1000 - (now - lastReset)) / (60 * 1000));
            return res.status(429).json({
                success: false,
                message: `Silakan tunggu ${minutesLeft} menit sebelum request reset password lagi`
            });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetExpires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

        // Update user
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetExpires.toISOString();
        user.lastPasswordReset = new Date().toISOString();
        user.updatedAt = new Date().toISOString();

        await database.save();

        // Send password reset email
        try {
            await emailService.sendPasswordResetEmail(user, resetToken);
            console.log('Password reset email sent to:', user.email);
        } catch (emailError) {
            console.error('Failed to send password reset email:', emailError);
            return res.status(500).json({
                success: false,
                message: 'Gagal mengirim email reset password'
            });
        }

        // Log reset request
        await database.logActivity({
            userId: user.id,
            type: 'password_reset_request',
            description: 'Password reset requested',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Instruksi reset password telah dikirim ke email Anda',
            data: {
                email: user.email,
                expiresIn: '1 jam'
            }
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat memproses permintaan reset password'
        });
    }
});

// ===== RESET PASSWORD =====
router.post('/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;

        if (!token || !password) {
            return res.status(400).json({
                success: false,
                message: 'Token dan password baru harus diisi'
            });
        }

        // Validate password
        if (!Security.validatePassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password minimal 8 karakter dengan 1 huruf besar dan 1 angka'
            });
        }

        // Find user by reset token
        const user = database.data.users.find(u => 
            u.resetPasswordToken === token && 
            u.resetPasswordExpires && 
            new Date(u.resetPasswordExpires) > new Date()
        );

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Token reset password tidak valid atau telah kadaluarsa'
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Update user
        user.password = hashedPassword;
        user.resetPasswordToken = null;
        user.resetPasswordExpires = null;
        user.loginAttempts = 0; // Reset failed attempts
        user.lastAttempt = null;
        user.lockedUntil = null;
        user.updatedAt = new Date().toISOString();

        await database.save();

        // Invalidate all user sessions (security measure)
        const userSessions = database.data.sessions.filter(s => s.userId === user.id);
        userSessions.forEach(session => {
            session.isValid = false;
        });

        // Log password reset
        await database.logActivity({
            userId: user.id,
            type: 'password_reset',
            description: 'Password reset successfully',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Password berhasil direset. Silakan login dengan password baru.',
            data: {
                userId: user.id,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat reset password'
        });
    }
});

// ===== CHECK SESSION =====
router.get('/session', async (req, res) => {
    try {
        if (!req.session.userId || !req.session.sessionId) {
            return res.json({ 
                success: false, 
                isLoggedIn: false 
            });
        }

        // Validate session in database
        const session = await database.validateSession(req.session.sessionId);
        if (!session) {
            req.session.destroy();
            return res.json({ 
                success: false, 
                isLoggedIn: false 
            });
        }

        // Get user data
        const user = await database.findUserById(req.session.userId);
        if (!user || !user.isActive) {
            req.session.destroy();
            return res.json({ 
                success: false, 
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
                isAdmin: user.isAdmin || false,
                needsVerification: !user.isVerified
            }
        });

    } catch (error) {
        res.json({ 
            success: false, 
            isLoggedIn: false 
        });
    }
});

// ===== VERIFY RESET TOKEN =====
router.get('/verify-reset-token/:token', async (req, res) => {
    try {
        const { token } = req.params;

        // Find user by reset token
        const user = database.data.users.find(u => 
            u.resetPasswordToken === token && 
            u.resetPasswordExpires && 
            new Date(u.resetPasswordExpires) > new Date()
        );

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Token reset password tidak valid atau telah kadaluarsa'
            });
        }

        res.json({
            success: true,
            data: {
                email: user.email,
                expiresAt: user.resetPasswordExpires
            }
        });

    } catch (error) {
        console.error('Verify reset token error:', error);
        res.status(500).json({
            success: false,
            message: 'Terjadi kesalahan saat memverifikasi token'
        });
    }
});

module.exports = router;
