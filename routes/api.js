const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');

const database = require('../utils/database');
const Security = require('../utils/security');
const whatsappManager = require('../utils/whatsapp-manager');
const { emailService } = require('../utils/email');
const { 
  authenticate, 
  requirePairing, 
  authorize, 
  rateLimitMiddleware,
  validateRequest,
  validateFileUpload 
} = require('../middleware/auth');
const Joi = require('joi');

// ===== RATE LIMITING =====
const broadcastRateLimit = rateLimitMiddleware(10, 60 * 60 * 1000); // 10 broadcasts per hour
const apiRateLimit = rateLimitMiddleware(100, 15 * 60 * 1000); // 100 requests per 15 minutes

// ===== VALIDATION SCHEMAS =====
const profileUpdateSchema = Joi.object({
  email: Joi.string().email().optional(),
  phone: Joi.string().pattern(/^[0-9]{10,15}$/).optional(),
  profile: Joi.object({
    fullName: Joi.string().min(2).max(100).optional(),
    company: Joi.string().max(100).optional(),
    avatar: Joi.string().uri().optional()
  }).optional()
});

const passwordChangeSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().min(6).required()
});

const pairingVerifySchema = Joi.object({
  code: Joi.string().length(6).pattern(/^[0-9]+$/).required()
});

const broadcastCreateSchema = Joi.object({
  title: Joi.string().min(3).max(200).required(),
  message: Joi.string().min(1).max(10000).required(),
  recipients: Joi.array().items(Joi.string().pattern(/^[0-9]{10,15}$/)).min(1).max(10000).required(),
  mediaUrl: Joi.string().uri().optional(),
  mediaType: Joi.string().valid('image', 'document', 'video', 'audio').optional(),
  schedule: Joi.object({
    enabled: Joi.boolean().default(false),
    date: Joi.date().greater('now').optional(),
    timezone: Joi.string().default('Asia/Jakarta')
  }).optional(),
  tags: Joi.array().items(Joi.string()).optional()
});

const broadcastUpdateSchema = Joi.object({
  title: Joi.string().min(3).max(200).optional(),
  message: Joi.string().min(1).max(10000).optional(),
  status: Joi.string().valid('draft', 'scheduled', 'processing', 'completed', 'cancelled').optional(),
  schedule: Joi.object({
    enabled: Joi.boolean(),
    date: Joi.date().greater('now'),
    timezone: Joi.string()
  }).optional()
});

const contactImportSchema = Joi.object({
  contacts: Joi.array().items(Joi.object({
    name: Joi.string().required(),
    phone: Joi.string().pattern(/^[0-9]{10,15}$/).required(),
    group: Joi.string().optional(),
    tags: Joi.array().items(Joi.string()).optional()
  })).min(1).max(1000).required()
});

// ===== USER PROFILE ROUTES =====

// Get user profile
router.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await database.findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User tidak ditemukan' 
      });
    }

    // Get user statistics
    const userStats = await database.getUserStats(user.id);
    
    // Remove sensitive data
    const { password, rememberToken, rememberExpires, verificationToken, ...safeUser } = user;
    
    res.json({ 
      success: true, 
      data: {
        ...safeUser,
        stats: userStats
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil data profil' 
    });
  }
});

// Update user profile
router.put('/profile', authenticate, validateRequest(profileUpdateSchema), async (req, res) => {
  try {
    const updates = {};
    
    // Validate and sanitize updates
    if (req.body.email) {
      const existingUser = await database.findUserByEmail(req.body.email);
      if (existingUser && existingUser.id !== req.user.id) {
        return res.status(400).json({ 
          success: false, 
          message: 'Email sudah digunakan oleh user lain' 
        });
      }
      updates.email = Security.sanitizeInput(req.body.email);
    }

    if (req.body.phone) {
      updates.phone = Security.sanitizeInput(req.body.phone);
    }

    if (req.body.profile) {
      updates.profile = {
        ...req.user.profile,
        ...req.body.profile
      };
    }

    const updatedUser = await database.updateUser(req.user.id, updates);
    if (!updatedUser) {
      return res.status(404).json({ 
        success: false, 
        message: 'User tidak ditemukan' 
      });
    }

    // Remove sensitive data
    const { password, rememberToken, rememberExpires, verificationToken, ...safeUser } = updatedUser;
    
    res.json({ 
      success: true, 
      data: safeUser, 
      message: 'Profil berhasil diperbarui' 
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat memperbarui profil' 
    });
  }
});

// Change password
router.post('/profile/change-password', authenticate, validateRequest(passwordChangeSchema), async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await database.findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User tidak ditemukan' 
      });
    }

    // Verify current password
    const isValid = await database.verifyPassword(user, currentPassword);
    if (!isValid) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password saat ini salah' 
      });
    }

    // Hash new password
    const hashedPassword = await Security.hashPassword(newPassword);
    
    // Update password
    await database.updateUser(req.user.id, { 
      password: hashedPassword.hash,
      salt: hashedPassword.salt,
      updatedAt: new Date().toISOString()
    });

    // Invalidate all sessions except current one
    await database.invalidateAllUserSessions(req.user.id, req.session.sessionId);

    // Send password change notification email
    try {
      await emailService.sendEmail(
        user.email,
        'Password Berhasil Diubah',
        'password-changed',
        {
          name: user.username,
          timestamp: new Date().toLocaleString('id-ID'),
          ipAddress: req.ip
        }
      );
    } catch (emailError) {
      console.error('Failed to send password change email:', emailError);
    }

    res.json({ 
      success: true, 
      message: 'Password berhasil diubah. Silakan login kembali.' 
    });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengubah password' 
    });
  }
});

// Upload profile picture
router.post('/profile/avatar', authenticate, validateFileUpload({
  maxSize: 2 * 1024 * 1024, // 2MB
  allowedTypes: ['image/jpeg', 'image/png', 'image/gif'],
  maxFiles: 1
}), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tidak ada file yang diupload' 
      });
    }

    const user = await database.findUserById(req.user.id);
    if (!user) {
      // Delete uploaded file
      await fs.unlink(req.file.path).catch(() => {});
      return res.status(404).json({ 
        success: false, 
        message: 'User tidak ditemukan' 
      });
    }

    // Delete old avatar if exists
    if (user.profile?.avatar) {
      const oldAvatarPath = path.join(__dirname, '..', 'uploads', path.basename(user.profile.avatar));
      await fs.unlink(oldAvatarPath).catch(() => {});
    }

    // Update user with new avatar
    const avatarUrl = `/uploads/${req.file.filename}`;
    await database.updateUser(req.user.id, {
      profile: {
        ...user.profile,
        avatar: avatarUrl,
        avatarUpdatedAt: new Date().toISOString()
      }
    });

    res.json({ 
      success: true, 
      data: { avatarUrl }, 
      message: 'Foto profil berhasil diupload' 
    });
  } catch (error) {
    console.error('Avatar upload error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat upload foto profil' 
    });
  }
});

// Get user statistics
router.get('/profile/stats', authenticate, async (req, res) => {
  try {
    const stats = await database.getUserStats(req.user.id);
    
    res.json({ 
      success: true, 
      data: stats 
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil statistik' 
    });
  }
});

// Get user activity log
router.get('/profile/activity', authenticate, async (req, res) => {
  try {
    const { limit = 50, page = 1 } = req.query;
    const activity = await database.getRecentActivity(req.user.id, parseInt(limit), parseInt(page));
    
    res.json({ 
      success: true, 
      data: activity 
    });
  } catch (error) {
    console.error('Activity log error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil aktivitas' 
    });
  }
});

// ===== PAIRING ROUTES =====

// Get pairing status
router.get('/pairing/status', authenticate, async (req, res) => {
  try {
    const pairingStatus = await database.getPairingStatus(req.user.id);
    const whatsappStatus = await whatsappManager.getStatus(req.user.id);
    
    res.json({ 
      success: true, 
      data: {
        pairing: pairingStatus,
        whatsapp: whatsappStatus
      }
    });
  } catch (error) {
    console.error('Pairing status error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil status pairing' 
    });
  }
});

// Generate pairing code
router.post('/pairing/generate', authenticate, async (req, res) => {
  try {
    // Check if user already has pending pairing
    const pendingPairing = await database.getPendingPairing(req.user.id);
    if (pendingPairing) {
      return res.json({ 
        success: true, 
        data: { code: pendingPairing.code }, 
        message: 'Kode pairing masih aktif' 
      });
    }

    const pairingCode = await database.createPairingCode(req.user.id);
    
    // Send email with pairing code
    try {
      const user = await database.findUserById(req.user.id);
      await emailService.sendVerificationEmail(user, pairingCode.code);
    } catch (emailError) {
      console.error('Failed to send pairing email:', emailError);
    }

    res.json({ 
      success: true, 
      data: { code: pairingCode.code }, 
      message: 'Kode pairing berhasil dibuat dan dikirim ke email Anda. Berlaku 10 menit.' 
    });
  } catch (error) {
    console.error('Pairing generate error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat membuat kode pairing' 
    });
  }
});

// Verify pairing
router.post('/pairing/verify', authenticate, validateRequest(pairingVerifySchema), async (req, res) => {
  try {
    const { code } = req.body;

    const isValid = await database.validatePairingCode(code, req.user.id);
    if (!isValid) {
      return res.status(400).json({ 
        success: false, 
        message: 'Kode pairing tidak valid atau sudah kedaluwarsa' 
      });
    }

    // Complete pairing
    const deviceInfo = {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      deviceId: req.headers['device-id'] || 'unknown'
    };

    const user = await database.completePairing(req.user.id, deviceInfo);
    
    // Initialize WhatsApp connection
    await whatsappManager.initialize(user.id);
    
    res.json({ 
      success: true, 
      message: 'Pairing berhasil! Akun Anda sekarang terverifikasi.' 
    });
  } catch (error) {
    console.error('Pairing verify error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat verifikasi pairing' 
    });
  }
});

// Get WhatsApp QR code
router.get('/whatsapp/qr', authenticate, requirePairing, async (req, res) => {
  try {
    const qrCode = await whatsappManager.getQRCode(req.user.id);
    if (!qrCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'WhatsApp sudah terhubung atau sedang dalam proses' 
      });
    }
    
    res.json({ 
      success: true, 
      data: { qrCode } 
    });
  } catch (error) {
    console.error('QR code error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
});

// Get WhatsApp status
router.get('/whatsapp/status', authenticate, requirePairing, async (req, res) => {
  try {
    const status = await whatsappManager.getStatus(req.user.id);
    
    res.json({ 
      success: true, 
      data: status 
    });
  } catch (error) {
    console.error('WhatsApp status error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil status WhatsApp' 
    });
  }
});

// Connect WhatsApp
router.post('/whatsapp/connect', authenticate, requirePairing, async (req, res) => {
  try {
    await whatsappManager.connect(req.user.id);
    
    res.json({ 
      success: true, 
      message: 'Koneksi WhatsApp sedang dipersiapkan' 
    });
  } catch (error) {
    console.error('WhatsApp connect error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
});

// Disconnect WhatsApp
router.post('/whatsapp/disconnect', authenticate, requirePairing, async (req, res) => {
  try {
    await whatsappManager.disconnect(req.user.id);
    
    res.json({ 
      success: true, 
      message: 'WhatsApp berhasil diputuskan' 
    });
  } catch (error) {
    console.error('WhatsApp disconnect error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
});

// ===== BROADCAST ROUTES =====

// Create broadcast
router.post('/broadcasts', authenticate, requirePairing, broadcastRateLimit, validateRequest(broadcastCreateSchema), async (req, res) => {
  try {
    const { title, message, recipients, mediaUrl, mediaType, schedule, tags } = req.body;

    // Check WhatsApp connection
    const whatsappStatus = await whatsappManager.getStatus(req.user.id);
    if (!whatsappStatus.isConnected) {
      return res.status(400).json({ 
        success: false, 
        message: 'WhatsApp tidak terhubung. Silakan sambungkan terlebih dahulu.' 
      });
    }

    const broadcastData = {
      title: Security.sanitizeInput(title),
      message: Security.sanitizeInput(message),
      recipients,
      mediaUrl,
      mediaType,
      schedule: schedule || { enabled: false },
      tags: tags || [],
      status: schedule?.enabled ? 'scheduled' : 'draft'
    };

    const broadcast = await database.createBroadcast(req.user.id, broadcastData);
    
    res.json({ 
      success: true, 
      data: broadcast, 
      message: 'Broadcast berhasil dibuat' 
    });
  } catch (error) {
    console.error('Broadcast create error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat membuat broadcast' 
    });
  }
});

// Get all broadcasts
router.get('/broadcasts', authenticate, requirePairing, async (req, res) => {
  try {
    const { limit = 50, page = 1, status, search } = req.query;
    
    const result = await database.getUserBroadcasts(
      req.user.id, 
      parseInt(limit), 
      parseInt(page),
      status,
      search
    );
    
    res.json({ 
      success: true, 
      data: result 
    });
  } catch (error) {
    console.error('Broadcasts list error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil daftar broadcast' 
    });
  }
});

// Get single broadcast
router.get('/broadcasts/:id', authenticate, requirePairing, async (req, res) => {
  try {
    const broadcast = await database.getBroadcastById(req.params.id);
    
    if (!broadcast || broadcast.userId !== req.user.id) {
      return res.status(404).json({ 
        success: false, 
        message: 'Broadcast tidak ditemukan' 
      });
    }
    
    res.json({ 
      success: true, 
      data: broadcast 
    });
  } catch (error) {
    console.error('Broadcast detail error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil detail broadcast' 
    });
  }
});

// Update broadcast
router.put('/broadcasts/:id', authenticate, requirePairing, validateRequest(broadcastUpdateSchema), async (req, res) => {
  try {
    const broadcast = await database.getBroadcastById(req.params.id);
    
    if (!broadcast || broadcast.userId !== req.user.id) {
      return res.status(404).json({ 
        success: false, 
        message: 'Broadcast tidak ditemukan' 
      });
    }

    if (['processing', 'completed'].includes(broadcast.status)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Broadcast yang sedang/sudah diproses tidak dapat diubah' 
      });
    }

    const updates = {};
    
    if (req.body.title) updates.title = Security.sanitizeInput(req.body.title);
    if (req.body.message) updates.message = Security.sanitizeInput(req.body.message);
    if (req.body.status) updates.status = req.body.status;
    if (req.body.schedule) updates.schedule = req.body.schedule;

    const updatedBroadcast = await database.updateBroadcast(req.params.id, updates);
    
    res.json({ 
      success: true, 
      data: updatedBroadcast, 
      message: 'Broadcast berhasil diperbarui' 
    });
  } catch (error) {
    console.error('Broadcast update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat memperbarui broadcast' 
    });
  }
});

// Send broadcast
router.post('/broadcasts/:id/send', authenticate, requirePairing, async (req, res) => {
  try {
    const broadcast = await database.getBroadcastById(req.params.id);
    
    if (!broadcast || broadcast.userId !== req.user.id) {
      return res.status(404).json({ 
        success: false, 
        message: 'Broadcast tidak ditemukan' 
      });
    }

    if (broadcast.status === 'processing') {
      return res.status(400).json({ 
        success: false, 
        message: 'Broadcast sedang dalam proses pengiriman' 
      });
    }

    if (broadcast.status === 'completed') {
      return res.status(400).json({ 
        success: false, 
        message: 'Broadcast sudah selesai dikirim' 
      });
    }

    // Check WhatsApp connection
    const whatsappStatus = await whatsappManager.getStatus(req.user.id);
    if (!whatsappStatus.isConnected) {
      return res.status(400).json({ 
        success: false, 
        message: 'WhatsApp tidak terhubung' 
      });
    }

    // Update broadcast status
    await database.updateBroadcast(broadcast.id, {
      status: 'processing',
      startedAt: new Date().toISOString()
    });

    // Send broadcast asynchronously
    whatsappManager.sendBroadcast(req.user.id, broadcast)
      .then(async (results) => {
        const sentCount = results.filter(r => r.status === 'success').length;
        const failedCount = results.filter(r => r.status === 'failed').length;
        
        await database.updateBroadcast(broadcast.id, {
          status: sentCount > 0 ? 'completed' : 'failed',
          sentCount: sentCount,
          failedCount: failedCount,
          completedAt: new Date().toISOString(),
          results: results
        });

        // Send email notification
        try {
          const user = await database.findUserById(req.user.id);
          await emailService.sendBroadcastStatusEmail(user, {
            ...broadcast,
            sentCount,
            failedCount,
            status: sentCount > 0 ? 'completed' : 'failed'
          });
        } catch (emailError) {
          console.error('Failed to send broadcast status email:', emailError);
        }
      })
      .catch(async (error) => {
        console.error('Broadcast sending error:', error);
        
        await database.updateBroadcast(broadcast.id, {
          status: 'failed',
          error: error.message,
          completedAt: new Date().toISOString()
        });
      });

    res.json({ 
      success: true, 
      message: 'Broadcast sedang dikirim. Anda akan menerima notifikasi email saat selesai.' 
    });
  } catch (error) {
    console.error('Broadcast send error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengirim broadcast' 
    });
  }
});

// Cancel broadcast
router.post('/broadcasts/:id/cancel', authenticate, requirePairing, async (req, res) => {
  try {
    const broadcast = await database.getBroadcastById(req.params.id);
    
    if (!broadcast || broadcast.userId !== req.user.id) {
      return res.status(404).json({ 
        success: false, 
        message: 'Broadcast tidak ditemukan' 
      });
    }

    if (!['draft', 'scheduled'].includes(broadcast.status)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Hanya broadcast draft atau scheduled yang dapat dibatalkan' 
      });
    }

    await database.updateBroadcast(broadcast.id, {
      status: 'cancelled',
      cancelledAt: new Date().toISOString()
    });
    
    res.json({ 
      success: true, 
      message: 'Broadcast berhasil dibatalkan' 
    });
  } catch (error) {
    console.error('Broadcast cancel error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat membatalkan broadcast' 
    });
  }
});

// Delete broadcast
router.delete('/broadcasts/:id', authenticate, requirePairing, async (req, res) => {
  try {
    const broadcast = await database.getBroadcastById(req.params.id);
    
    if (!broadcast || broadcast.userId !== req.user.id) {
      return res.status(404).json({ 
        success: false, 
        message: 'Broadcast tidak ditemukan' 
      });
    }

    if (broadcast.status === 'processing') {
      return res.status(400).json({ 
        success: false, 
        message: 'Broadcast sedang diproses, tidak dapat dihapus' 
      });
    }

    const deleted = await database.deleteBroadcast(req.params.id);
    
    if (!deleted) {
      return res.status(500).json({ 
        success: false, 
        message: 'Gagal menghapus broadcast' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Broadcast berhasil dihapus' 
    });
  } catch (error) {
    console.error('Broadcast delete error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat menghapus broadcast' 
    });
  }
});

// Get broadcast statistics
router.get('/broadcasts/:id/stats', authenticate, requirePairing, async (req, res) => {
  try {
    const broadcast = await database.getBroadcastById(req.params.id);
    
    if (!broadcast || broadcast.userId !== req.user.id) {
      return res.status(404).json({ 
        success: false, 
        message: 'Broadcast tidak ditemukan' 
      });
    }

    const stats = {
      totalRecipients: broadcast.totalRecipients || broadcast.recipients?.length || 0,
      sentCount: broadcast.sentCount || 0,
      failedCount: broadcast.failedCount || 0,
      successRate: 0,
      averageDeliveryTime: null,
      startedAt: broadcast.startedAt,
      completedAt: broadcast.completedAt,
      duration: null
    };

    if (stats.totalRecipients > 0) {
      stats.successRate = (stats.sentCount / stats.totalRecipients) * 100;
    }

    if (broadcast.startedAt && broadcast.completedAt) {
      const start = new Date(broadcast.startedAt);
      const end = new Date(broadcast.completedAt);
      stats.duration = Math.round((end - start) / 1000); // in seconds
    }

    res.json({ 
      success: true, 
      data: stats 
    });
  } catch (error) {
    console.error('Broadcast stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil statistik broadcast' 
    });
  }
});

// ===== CONTACT MANAGEMENT ROUTES =====

// Import contacts
router.post('/contacts/import', authenticate, requirePairing, validateRequest(contactImportSchema), async (req, res) => {
  try {
    const { contacts } = req.body;
    
    // Validate and sanitize contacts
    const sanitizedContacts = contacts.map(contact => ({
      name: Security.sanitizeInput(contact.name),
      phone: contact.phone.replace(/\D/g, ''), // Remove non-numeric characters
      group: contact.group ? Security.sanitizeInput(contact.group) : 'default',
      tags: contact.tags || [],
      importedAt: new Date().toISOString(),
      userId: req.user.id
    }));

    // Save contacts to database (you need to implement this in database.js)
    await database.saveContacts(req.user.id, sanitizedContacts);
    
    res.json({ 
      success: true, 
      data: { importedCount: contacts.length }, 
      message: `${contacts.length} kontak berhasil diimport` 
    });
  } catch (error) {
    console.error('Contact import error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat import kontak' 
    });
  }
});

// Get contacts
router.get('/contacts', authenticate, requirePairing, async (req, res) => {
  try {
    const { limit = 100, page = 1, group, search } = req.query;
    const contacts = await database.getContacts(
      req.user.id, 
      parseInt(limit), 
      parseInt(page),
      group,
      search
    );
    
    res.json({ 
      success: true, 
      data: contacts 
    });
  } catch (error) {
    console.error('Contacts list error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil daftar kontak' 
    });
  }
});

// ===== SYSTEM ROUTES =====

// Get system status
router.get('/system/status', authenticate, async (req, res) => {
  try {
    const user = await database.findUserById(req.user.id);
    const pairingStatus = await database.getPairingStatus(req.user.id);
    const whatsappStatus = await whatsappManager.getStatus(req.user.id);
    const userStats = await database.getUserStats(req.user.id);
    
    res.json({ 
      success: true, 
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          isVerified: user.isVerified,
          pairingStatus: user.pairingStatus
        },
        pairing: pairingStatus,
        whatsapp: whatsappStatus,
        stats: userStats,
        server: {
          timestamp: new Date().toISOString(),
          uptime: process.uptime()
        }
      }
    });
  } catch (error) {
    console.error('System status error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Terjadi kesalahan saat mengambil status sistem' 
    });
  }
});

// Get API documentation
router.get('/docs', authenticate, (req, res) => {
  const docs = {
    endpoints: {
      profile: {
        GET: '/api/profile - Get user profile',
        PUT: '/api/profile - Update profile',
        POST: '/api/profile/change-password - Change password',
        POST: '/api/profile/avatar - Upload avatar'
      },
      pairing: {
        GET: '/api/pairing/status - Get pairing status',
        POST: '/api/pairing/generate - Generate pairing code',
        POST: '/api/pairing/verify - Verify pairing code'
      },
      whatsapp: {
        GET: '/api/whatsapp/qr - Get QR code',
        GET: '/api/whatsapp/status - Get WhatsApp status',
        POST: '/api/whatsapp/connect - Connect WhatsApp',
        POST: '/api/whatsapp/disconnect - Disconnect WhatsApp'
      },
      broadcasts: {
        POST: '/api/broadcasts - Create broadcast',
        GET: '/api/broadcasts - List broadcasts',
        GET: '/api/broadcasts/:id - Get broadcast details',
        PUT: '/api/broadcasts/:id - Update broadcast',
        POST: '/api/broadcasts/:id/send - Send broadcast',
        POST: '/api/broadcasts/:id/cancel - Cancel broadcast',
        DELETE: '/api/broadcasts/:id - Delete broadcast',
        GET: '/api/broadcasts/:id/stats - Get broadcast stats'
      },
      contacts: {
        POST: '/api/contacts/import - Import contacts',
        GET: '/api/contacts - List contacts'
      },
      system: {
        GET: '/api/system/status - Get system status'
      }
    },
    authentication: 'All endpoints require authentication token in header',
    rateLimiting: 'Rate limits apply to all endpoints',
    version: '1.0.0'
  };
  
  res.json({ success: true, data: docs });
});

// ===== LOGOUT =====
router.post('/logout', authenticate, async (req, res) => {
  try {
    // Invalidate session
    if (req.session.sessionId) {
      await database.invalidateSession(req.session.sessionId);
    }
    
    // Disconnect WhatsApp
    try {
      await whatsappManager.disconnect(req.user.id);
    } catch (whatsappError) {
      console.error('WhatsApp disconnect error during logout:', whatsappError);
    }
    
    // Clear remember me cookie
    if (req.cookies.remember_me) {
      await database.clearRememberToken(req.user.id);
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

module.exports = router;
