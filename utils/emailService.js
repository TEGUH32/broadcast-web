const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');

class EmailService {
    constructor() {
        this.transporter = null;
        this.templates = {};
        this.init();
    }

    async init() {
        try {
            // Load email configuration
            const config = {
                service: process.env.EMAIL_SERVICE || 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                },
                pool: true,
                maxConnections: 5,
                maxMessages: 100
            };

            if (!config.auth.user || !config.auth.pass) {
                console.warn('⚠️ Email credentials not configured. Email functionality will be limited.');
                return;
            }

            this.transporter = nodemailer.createTransport(config);

            // Verify connection
            await this.transporter.verify();
            console.log('✅ Email service initialized successfully');

            // Load email templates
            await this.loadTemplates();

        } catch (error) {
            console.error('❌ Email service initialization failed:', error.message);
            this.transporter = null;
        }
    }

    async loadTemplates() {
        try {
            const templatesDir = path.join(__dirname, '../email-templates');
            
            // Create templates directory if it doesn't exist
            await fs.mkdir(templatesDir, { recursive: true });
            
            // Load default templates
            this.templates = {
                verification: await this.getTemplate('verification'),
                welcome: await this.getTemplate('welcome'),
                passwordReset: await this.getTemplate('password-reset'),
                broadcastNotification: await this.getTemplate('broadcast-notification')
            };

        } catch (error) {
            console.error('Error loading email templates:', error);
            this.templates = this.getDefaultTemplates();
        }
    }

    async getTemplate(name) {
        try {
            const templatePath = path.join(__dirname, `../email-templates/${name}.html`);
            return await fs.readFile(templatePath, 'utf8');
        } catch (error) {
            return this.getDefaultTemplate(name);
        }
    }

    getDefaultTemplate(name) {
        const templates = {
            verification: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifikasi Email - WhatsApp Broadcast Bot</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
        .code { background: white; border: 2px dashed #667eea; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 10px; margin: 20px 0; border-radius: 10px; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; font-size: 12px; }
        .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verifikasi Email</h1>
            <p>Aktifkan akun WhatsApp Broadcast Bot Anda</p>
        </div>
        <div class="content">
            <p>Halo {name},</p>
            <p>Terima kasih telah mendaftar di WhatsApp Broadcast Bot. Untuk mengaktifkan akun Anda, silakan verifikasi email Anda dengan kode berikut:</p>
            
            <div class="code">{verificationCode}</div>
            
            <p>Kode verifikasi ini akan kadaluarsa dalam <strong>10 menit</strong>.</p>
            
            <p>Jika Anda tidak merasa mendaftar, silakan abaikan email ini.</p>
            
            <p>Terima kasih,<br>Tim WhatsApp Broadcast Bot</p>
        </div>
        <div class="footer">
            <p>Email ini dikirim secara otomatis, mohon tidak membalas email ini.</p>
            <p>© {year} WhatsApp Broadcast Bot. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            `,

            welcome: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Selamat Datang - WhatsApp Broadcast Bot</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
        .features { margin: 20px 0; }
        .feature-item { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #667eea; border-radius: 5px; }
        .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Selamat Datang!</h1>
            <p>Akun Anda telah aktif dan siap digunakan</p>
        </div>
        <div class="content">
            <p>Halo {name},</p>
            <p>Selamat! Akun WhatsApp Broadcast Bot Anda telah berhasil diverifikasi dan sekarang aktif.</p>
            
            <div class="features">
                <h3>Fitur yang dapat Anda gunakan:</h3>
                <div class="feature-item">
                    <strong>📤 Broadcast Massal</strong>
                    <p>Kirim pesan ke ribuan kontak sekaligus</p>
                </div>
                <div class="feature-item">
                    <strong>⏰ Penjadwalan</strong>
                    <p>Atur waktu pengiriman pesan secara otomatis</p>
                </div>
                <div class="feature-item">
                    <strong>📊 Analytics</strong>
                    <p>Pantau statistik dan performa broadcast</p>
                </div>
            </div>
            
            <p>Mulai dengan mengakses dashboard Anda:</p>
            <a href="{dashboardUrl}" class="button">Masuk ke Dashboard</a>
            
            <p>Jika Anda memiliki pertanyaan, jangan ragu untuk menghubungi tim support kami.</p>
            
            <p>Terima kasih,<br>Tim WhatsApp Broadcast Bot</p>
        </div>
        <div class="footer">
            <p>Email ini dikirim secara otomatis, mohon tidak membalas email ini.</p>
            <p>© {year} WhatsApp Broadcast Bot. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            `,

            passwordReset: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - WhatsApp Broadcast Bot</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
        .code { background: white; border: 2px dashed #667eea; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; margin: 20px 0; border-radius: 10px; word-break: break-all; }
        .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; font-size: 12px; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reset Password</h1>
            <p>Permintaan reset password akun Anda</p>
        </div>
        <div class="content">
            <p>Halo {name},</p>
            <p>Kami menerima permintaan reset password untuk akun WhatsApp Broadcast Bot Anda.</p>
            
            <div class="warning">
                <strong>⚠️ Perhatian:</strong>
                <p>Jika Anda tidak melakukan permintaan reset password, silakan abaikan email ini. Akun Anda tetap aman.</p>
            </div>
            
            <p>Untuk mereset password Anda, silakan klik link berikut:</p>
            
            <a href="{resetLink}" class="button">Reset Password Saya</a>
            
            <p>Atau copy dan paste link berikut di browser Anda:</p>
            <div class="code">{resetLink}</div>
            
            <p>Link reset password ini akan kadaluarsa dalam <strong>1 jam</strong>.</p>
            
            <p>Terima kasih,<br>Tim WhatsApp Broadcast Bot</p>
        </div>
        <div class="footer">
            <p>Email ini dikirim secara otomatis, mohon tidak membalas email ini.</p>
            <p>© {year} WhatsApp Broadcast Bot. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            `,

            broadcastNotification: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifikasi Broadcast - WhatsApp Broadcast Bot</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 20px 0; }
        .stat-item { background: white; padding: 15px; text-align: center; border-radius: 5px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #667eea; }
        .stat-label { font-size: 12px; color: #666; }
        .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Broadcast Selesai</h1>
            <p>Notifikasi hasil broadcast Anda</p>
        </div>
        <div class="content">
            <p>Halo {name},</p>
            <p>Broadcast Anda telah selesai dikirim. Berikut adalah hasilnya:</p>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-value">{sentCount}</div>
                    <div class="stat-label">Terkirim</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{failedCount}</div>
                    <div class="stat-label">Gagal</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{successRate}%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
            </div>
            
            <p><strong>Nama Broadcast:</strong> {broadcastName}</p>
            <p><strong>Waktu Selesai:</strong> {completedAt}</p>
            <p><strong>Total Penerima:</strong> {totalContacts} kontak</p>
            
            <p>Untuk melihat detail lengkap, kunjungi dashboard Anda:</p>
            <a href="{dashboardUrl}" class="button">Lihat Detail Broadcast</a>
            
            <p>Terima kasih,<br>Tim WhatsApp Broadcast Bot</p>
        </div>
        <div class="footer">
            <p>Email ini dikirim secara otomatis, mohon tidak membalas email ini.</p>
            <p>© {year} WhatsApp Broadcast Bot. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
            `
        };

        return templates[name] || '';
    }

    getDefaultTemplates() {
        return {
            verification: this.getDefaultTemplate('verification'),
            welcome: this.getDefaultTemplate('welcome'),
            passwordReset: this.getDefaultTemplate('passwordReset'),
            broadcastNotification: this.getDefaultTemplate('broadcastNotification')
        };
    }

    async sendEmail(to, subject, html, text = '') {
        if (!this.transporter) {
            console.warn('Email service not initialized. Email not sent to:', to);
            return false;
        }

        try {
            const mailOptions = {
                from: `"WhatsApp Broadcast Bot" <${process.env.EMAIL_USER}>`,
                to,
                subject,
                html,
                text: text || html.replace(/<[^>]*>/g, ''),
                headers: {
                    'X-Priority': '3',
                    'X-Mailer': 'WhatsApp Broadcast Bot',
                    'List-Unsubscribe': `<https://${process.env.DOMAIN || 'localhost'}/unsubscribe>`
                }
            };

            const info = await this.transporter.sendMail(mailOptions);
            
            // Log email sent
            await this.logEmail({
                to,
                subject,
                messageId: info.messageId,
                status: 'sent'
            });

            console.log(`📧 Email sent to ${to}: ${info.messageId}`);
            return true;

        } catch (error) {
            console.error('Error sending email:', error);
            
            // Log email failure
            await this.logEmail({
                to,
                subject,
                error: error.message,
                status: 'failed'
            });

            return false;
        }
    }

    async logEmail(logData) {
        try {
            const logsDir = path.join(__dirname, '../logs');
            await fs.mkdir(logsDir, { recursive: true });
            
            const logEntry = {
                timestamp: new Date().toISOString(),
                ...logData
            };
            
            const logFile = path.join(logsDir, 'email.log');
            await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
        } catch (error) {
            console.error('Error logging email:', error);
        }
    }

    replaceTemplateVariables(template, variables) {
        let result = template;
        for (const [key, value] of Object.entries(variables)) {
            result = result.replace(new RegExp(`{${key}}`, 'g'), value);
        }
        return result;
    }

    // ===== SPECIFIC EMAIL FUNCTIONS =====

    async sendVerificationEmail(user, verificationCode) {
        if (!user.email) {
            throw new Error('User email is required');
        }

        const template = this.templates.verification || this.getDefaultTemplate('verification');
        
        const variables = {
            name: user.username || user.email.split('@')[0],
            verificationCode,
            year: new Date().getFullYear().toString()
        };

        const html = this.replaceTemplateVariables(template, variables);
        const subject = 'Verifikasi Email - WhatsApp Broadcast Bot';

        return await this.sendEmail(user.email, subject, html);
    }

    async sendWelcomeEmail(user) {
        if (!user.email) {
            throw new Error('User email is required');
        }

        const template = this.templates.welcome || this.getDefaultTemplate('welcome');
        
        const variables = {
            name: user.username || user.email.split('@')[0],
            dashboardUrl: `${process.env.APP_URL || 'http://localhost:8000'}/dashboard.html`,
            year: new Date().getFullYear().toString()
        };

        const html = this.replaceTemplateVariables(template, variables);
        const subject = 'Selamat Datang di WhatsApp Broadcast Bot!';

        return await this.sendEmail(user.email, subject, html);
    }

    async sendPasswordResetEmail(user, resetToken) {
        if (!user.email) {
            throw new Error('User email is required');
        }

        const template = this.templates.passwordReset || this.getDefaultTemplate('passwordReset');
        
        const resetLink = `${process.env.APP_URL || 'http://localhost:8000'}/reset-password.html?token=${resetToken}`;
        
        const variables = {
            name: user.username || user.email.split('@')[0],
            resetLink,
            year: new Date().getFullYear().toString()
        };

        const html = this.replaceTemplateVariables(template, variables);
        const subject = 'Reset Password - WhatsApp Broadcast Bot';

        return await this.sendEmail(user.email, subject, html);
    }

    async sendBroadcastNotification(user, broadcastData) {
        if (!user.email) {
            throw new Error('User email is required');
        }

        const template = this.templates.broadcastNotification || this.getDefaultTemplate('broadcastNotification');
        
        const successRate = broadcastData.totalContacts > 0 
            ? Math.round((broadcastData.sentCount / broadcastData.totalContacts) * 100)
            : 0;

        const variables = {
            name: user.username || user.email.split('@')[0],
            broadcastName: broadcastData.name,
            sentCount: broadcastData.sentCount || 0,
            failedCount: broadcastData.failedCount || 0,
            successRate,
            totalContacts: broadcastData.totalContacts || 0,
            completedAt: new Date().toLocaleString('id-ID'),
            dashboardUrl: `${process.env.APP_URL || 'http://localhost:8000'}/dashboard.html`,
            year: new Date().getFullYear().toString()
        };

        const html = this.replaceTemplateVariables(template, variables);
        const subject = `Broadcast Selesai: ${broadcastData.name}`;

        return await this.sendEmail(user.email, subject, html);
    }

    // ===== BULK EMAIL FUNCTIONS =====

    async sendBulkVerificationEmails(users) {
        const results = {
            success: 0,
            failed: 0,
            details: []
        };

        for (const user of users) {
            try {
                const code = Math.floor(100000 + Math.random() * 900000).toString();
                const success = await this.sendVerificationEmail(user, code);
                
                results.details.push({
                    email: user.email,
                    status: success ? 'success' : 'failed'
                });

                if (success) {
                    results.success++;
                } else {
                    results.failed++;
                }
            } catch (error) {
                results.details.push({
                    email: user.email,
                    status: 'error',
                    error: error.message
                });
                results.failed++;
            }
        }

        return results;
    }

    // ===== EMAIL TEMPLATE MANAGEMENT =====

    async saveTemplate(name, html) {
        try {
            const templatesDir = path.join(__dirname, '../email-templates');
            await fs.mkdir(templatesDir, { recursive: true });
            
            const templatePath = path.join(templatesDir, `${name}.html`);
            await fs.writeFile(templatePath, html, 'utf8');
            
            // Reload templates
            this.templates[name] = html;
            
            return true;
        } catch (error) {
            console.error('Error saving template:', error);
            return false;
        }
    }

    async getEmailStats() {
        try {
            const logFile = path.join(__dirname, '../logs/email.log');
            
            if (!await fs.access(logFile).then(() => true).catch(() => false)) {
                return { total: 0, sent: 0, failed: 0 };
            }
            
            const content = await fs.readFile(logFile, 'utf8');
            const lines = content.trim().split('\n');
            
            const stats = {
                total: lines.length,
                sent: 0,
                failed: 0,
                last24Hours: 0
            };
            
            const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000);
            
            for (const line of lines) {
                try {
                    const log = JSON.parse(line);
                    
                    if (log.status === 'sent') {
                        stats.sent++;
                    } else if (log.status === 'failed') {
                        stats.failed++;
                    }
                    
                    const logTime = new Date(log.timestamp).getTime();
                    if (logTime > twentyFourHoursAgo) {
                        stats.last24Hours++;
                    }
                } catch (e) {
                    // Skip invalid JSON lines
                }
            }
            
            return stats;
        } catch (error) {
            console.error('Error getting email stats:', error);
            return { total: 0, sent: 0, failed: 0, last24Hours: 0 };
        }
    }
}

// Create singleton instance
const emailService = new EmailService();

// Export functions for backward compatibility
module.exports = {
    sendVerificationEmail: async (user, code) => {
        return await emailService.sendVerificationEmail(user, code);
    },
    sendWelcomeEmail: async (user) => {
        return await emailService.sendWelcomeEmail(user);
    },
    sendPasswordResetEmail: async (user, token) => {
        return await emailService.sendPasswordResetEmail(user, token);
    },
    sendBroadcastNotification: async (user, data) => {
        return await emailService.sendBroadcastNotification(user, data);
    },
    sendEmail: async (to, subject, html, text) => {
        return await emailService.sendEmail(to, subject, html, text);
    },
    emailService // Export the service instance
};
