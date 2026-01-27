const database = require('../utils/database');
const Security = require('../utils/security');

const authenticate = async (req, res, next) => {
  try {
    // Check session
    if (!req.session || !req.session.userId || !req.session.sessionId) {
      return res.status(401).json({ 
        success: false, 
        message: 'Sesi tidak valid, silakan login ulang' 
      });
    }

    // Validate session in database
    const session = await database.validateSession(req.session.sessionId);
    if (!session) {
      req.session.destroy();
      return res.status(401).json({ 
        success: false, 
        message: 'Sesi telah kedaluwarsa' 
      });
    }

    // Check user exists and is active
    const user = await database.findUserById(req.session.userId);
    if (!user || !user.isActive) {
      req.session.destroy();
      return res.status(401).json({ 
        success: false, 
        message: 'Akun tidak ditemukan atau tidak aktif' 
      });
    }

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(403).json({ 
        success: false, 
        message: 'Akun belum diverifikasi, selesaikan pairing terlebih dahulu' 
      });
    }

    // Update last active
    req.session.lastActive = Date.now();
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Kesalahan autentikasi' 
    });
  }
};

const requirePairing = async (req, res, next) => {
  if (!req.user.isVerified) {
    return res.status(403).json({ 
      success: false, 
      message: 'Pairing WhatsApp diperlukan' 
    });
  }
  next();
};

module.exports = { authenticate, requirePairing };
