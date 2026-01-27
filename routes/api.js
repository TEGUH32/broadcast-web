const express = require('express');
const router = express.Router();
const database = require('../utils/database');
const Security = require('../utils/security');
const whatsappPairing = require('../utils/pairing');
const { requirePairing } = require('../middleware/auth');

// User profile
router.get('/profile', async (req, res) => {
  try {
    const user = await database.findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    }

    // Remove sensitive data
    const { password, pairingCode, ...safeUser } = user;
    res.json({ success: true, data: safeUser });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.put('/profile', async (req, res) => {
  try {
    const updates = {};
    
    if (req.body.email) {
      if (!Security.validateEmail(req.body.email)) {
        return res.status(400).json({ success: false, message: 'Format email tidak valid' });
      }
      updates.email = Security.sanitizeInput(req.body.email);
    }

    const updatedUser = await database.updateUser(req.user.id, updates);
    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    }

    const { password, pairingCode, ...safeUser } = updatedUser;
    res.json({ success: true, data: safeUser, message: 'Profil berhasil diperbarui' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Generate pairing code
router.post('/pairing/generate', async (req, res) => {
  try {
    const code = await database.createPairingCode(req.user.id);
    res.json({ 
      success: true, 
      data: { code }, 
      message: 'Kode pairing berhasil dibuat. Berlaku 10 menit.' 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Verify pairing
router.post('/pairing/verify', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code || code.length !== 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Kode pairing harus 6 digit' 
      });
    }

    const isValid = await database.validatePairingCode(code, req.user.id);
    if (!isValid) {
      return res.status(400).json({ 
        success: false, 
        message: 'Kode pairing tidak valid atau sudah kedaluwarsa' 
      });
    }

    // Mark user as verified
    await database.updateUser(req.user.id, { 
      isVerified: true,
      pairingCode: code 
    });

    res.json({ 
      success: true, 
      message: 'Pairing berhasil! Akun Anda sekarang terverifikasi.' 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// WhatsApp connection
router.post('/whatsapp/connect', requirePairing, async (req, res) => {
  try {
    await whatsappPairing.createConnection(req.user.id);
    res.json({ 
      success: true, 
      message: 'Koneksi WhatsApp sedang dipersiapkan' 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.get('/whatsapp/qr', requirePairing, async (req, res) => {
  try {
    const qrCode = await whatsappPairing.getQRCode(req.user.id);
    res.json({ success: true, data: { qrCode } });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

router.get('/whatsapp/status', requirePairing, async (req, res) => {
  try {
    const isConnected = await whatsappPairing.checkConnection(req.user.id);
    res.json({ success: true, data: { isConnected } });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Broadcast management
router.post('/broadcasts', requirePairing, async (req, res) => {
  try {
    const { name, message, contacts, scheduledFor } = req.body;

    if (!name || !message || !contacts || !Array.isArray(contacts)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Data broadcast tidak lengkap' 
      });
    }

    const broadcast = await database.createBroadcast(req.user.id, {
      name: Security.sanitizeInput(name),
      message: Security.sanitizeInput(message),
      contacts,
      scheduledFor
    });

    res.json({ 
      success: true, 
      data: broadcast, 
      message: 'Broadcast berhasil dibuat' 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.get('/broadcasts', requirePairing, async (req, res) => {
  try {
    const broadcasts = await database.getUserBroadcasts(req.user.id);
    res.json({ success: true, data: broadcasts });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.post('/broadcasts/:id/send', requirePairing, async (req, res) => {
  try {
    const broadcast = database.data.broadcasts.find(b => 
      b.id === req.params.id && b.userId === req.user.id
    );

    if (!broadcast) {
      return res.status(404).json({ 
        success: false, 
        message: 'Broadcast tidak ditemukan' 
      });
    }

    // Check WhatsApp connection
    const isConnected = await whatsappPairing.checkConnection(req.user.id);
    if (!isConnected) {
      return res.status(400).json({ 
        success: false, 
        message: 'Koneksi WhatsApp tidak aktif' 
      });
    }

    // Send broadcast
    const results = await whatsappPairing.sendBroadcast(
      req.user.id, 
      broadcast.contacts, 
      broadcast.message
    );

    // Update broadcast stats
    const sentCount = results.filter(r => r.status === 'success').length;
    const failedCount = results.filter(r => r.status === 'failed').length;
    
    await database.updateBroadcast(broadcast.id, {
      status: sentCount > 0 ? 'sent' : 'failed',
      sentCount: broadcast.sentCount + sentCount,
      failedCount: broadcast.failedCount + failedCount,
      lastSentAt: new Date().toISOString()
    });

    res.json({ 
      success: true, 
      data: { results },
      message: `Broadcast dikirim: ${sentCount} berhasil, ${failedCount} gagal` 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  try {
    if (req.session.sessionId) {
      await database.invalidateSession(req.session.sessionId);
    }
    
    // Disconnect WhatsApp if connected
    await whatsappPairing.disconnect(req.user.id);
    
    req.session.destroy();
    res.json({ success: true, message: 'Logout berhasil' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
