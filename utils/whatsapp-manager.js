const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');
const logger = require('./logger');

class WhatsAppManager extends EventEmitter {
  constructor() {
    super();
    this.clients = new Map(); // userId -> whatsapp client
    this.sessions = new Map(); // userId -> session data
    this.qrCodes = new Map(); // userId -> qr code
    this.initializeCleanupInterval();
  }

  initializeCleanupInterval() {
    // Cleanup inactive sessions every 5 minutes
    setInterval(() => this.cleanupInactiveSessions(), 5 * 60 * 1000);
  }

  async cleanupInactiveSessions() {
    const now = Date.now();
    for (const [userId, session] of this.sessions) {
      if (session.lastActivity && (now - session.lastActivity) > 30 * 60 * 1000) {
        // Session inactive for 30 minutes
        await this.disconnect(userId);
        logger.info(`Cleaned up inactive session for user ${userId}`);
      }
    }
  }

  async initialize(userId) {
    try {
      // Create sessions directory if not exists
      const sessionsDir = path.join(__dirname, '../sessions');
      await fs.mkdir(sessionsDir, { recursive: true });

      // Check if client already exists
      if (this.clients.has(userId)) {
        const client = this.clients.get(userId);
        if (client.isReady) {
          return { isInitialized: true, isConnected: true };
        }
      }

      // Create new client with session persistence
      const client = new Client({
        authStrategy: new LocalAuth({
          clientId: `user_${userId}`,
          dataPath: sessionsDir
        }),
        puppeteer: {
          headless: true,
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process'
          ]
        },
        webVersionCache: {
          type: 'remote',
          remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2412.54.html'
        },
        qrMaxRetries: 3,
        takeoverOnConflict: true,
        takeoverTimeoutMs: 5000
      });

      // Store client
      this.clients.set(userId, client);
      this.sessions.set(userId, {
        client,
        status: 'initializing',
        lastActivity: Date.now(),
        isConnected: false,
        userInfo: null
      });

      // Setup event handlers
      this.setupClientEvents(userId, client);

      // Initialize client
      await client.initialize();

      return { isInitialized: true, isConnected: false };
    } catch (error) {
      logger.error(`Failed to initialize WhatsApp for user ${userId}:`, error);
      throw new Error(`Gagal menginisialisasi WhatsApp: ${error.message}`);
    }
  }

  setupClientEvents(userId, client) {
    // QR Code generation
    client.on('qr', async (qr) => {
      try {
        const qrImage = await qrcode.toDataURL(qr);
        this.qrCodes.set(userId, qrImage);
        this.sessions.get(userId).status = 'waiting_qr';
        
        this.emit('qr', userId, qrImage);
        logger.info(`QR code generated for user ${userId}`);
      } catch (error) {
        logger.error(`Failed to generate QR code for user ${userId}:`, error);
      }
    });

    // Authenticated
    client.on('authenticated', () => {
      const session = this.sessions.get(userId);
      session.status = 'authenticated';
      session.lastActivity = Date.now();
      
      this.emit('authenticated', userId);
      logger.info(`User ${userId} authenticated with WhatsApp`);
    });

    // Ready
    client.on('ready', () => {
      const session = this.sessions.get(userId);
      session.status = 'ready';
      session.isConnected = true;
      session.lastActivity = Date.now();
      session.client = client;
      
      // Clear QR code
      this.qrCodes.delete(userId);
      
      this.emit('ready', userId);
      logger.info(`WhatsApp client ready for user ${userId}`);
    });

    // Disconnected
    client.on('disconnected', (reason) => {
      const session = this.sessions.get(userId);
      session.status = 'disconnected';
      session.isConnected = false;
      session.disconnectReason = reason;
      
      this.emit('disconnected', userId, reason);
      logger.warn(`WhatsApp disconnected for user ${userId}: ${reason}`);
      
      // Cleanup
      setTimeout(() => {
        if (this.clients.has(userId)) {
          this.clients.delete(userId);
          this.qrCodes.delete(userId);
        }
      }, 5000);
    });

    // Message
    client.on('message', async (message) => {
      // Update last activity on any message
      const session = this.sessions.get(userId);
      if (session) {
        session.lastActivity = Date.now();
      }
      
      // You can add custom message handling here
      this.emit('message', userId, message);
    });

    // Auth failure
    client.on('auth_failure', (msg) => {
      logger.error(`WhatsApp auth failure for user ${userId}:`, msg);
      this.emit('auth_failure', userId, msg);
    });

    // Loading screen
    client.on('loading_screen', (percent, message) => {
      logger.info(`User ${userId} loading screen: ${percent}% - ${message}`);
    });
  }

  async connect(userId) {
    try {
      const session = this.sessions.get(userId);
      if (!session) {
        await this.initialize(userId);
        return { success: true, needsQR: true };
      }

      if (session.isConnected) {
        return { success: true, isConnected: true };
      }

      if (session.status === 'waiting_qr') {
        return { success: true, needsQR: true };
      }

      // Reinitialize if disconnected
      if (session.status === 'disconnected') {
        await this.disconnect(userId);
        await this.initialize(userId);
        return { success: true, needsQR: true };
      }

      return { success: true, status: session.status };
    } catch (error) {
      logger.error(`Failed to connect WhatsApp for user ${userId}:`, error);
      throw new Error(`Gagal menghubungkan WhatsApp: ${error.message}`);
    }
  }

  async disconnect(userId) {
    try {
      const session = this.sessions.get(userId);
      if (session && session.client) {
        await session.client.destroy();
      }
      
      this.clients.delete(userId);
      this.sessions.delete(userId);
      this.qrCodes.delete(userId);
      
      logger.info(`WhatsApp disconnected for user ${userId}`);
      return { success: true };
    } catch (error) {
      logger.error(`Failed to disconnect WhatsApp for user ${userId}:`, error);
      throw new Error(`Gagal memutuskan WhatsApp: ${error.message}`);
    }
  }

  async getQRCode(userId) {
    try {
      // Check if client exists and is waiting for QR
      const session = this.sessions.get(userId);
      if (!session || session.status !== 'waiting_qr') {
        // Initialize new session
        await this.initialize(userId);
        
        // Wait a bit for QR generation
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      const qrCode = this.qrCodes.get(userId);
      if (!qrCode) {
        throw new Error('QR code belum tersedia. Silakan tunggu beberapa saat.');
      }

      return qrCode;
    } catch (error) {
      logger.error(`Failed to get QR code for user ${userId}:`, error);
      throw error;
    }
  }

  async getStatus(userId) {
    try {
      const session = this.sessions.get(userId);
      if (!session) {
        return {
          isConnected: false,
          status: 'not_initialized',
          lastActivity: null,
          userInfo: null
        };
      }

      const client = session.client;
      let userInfo = session.userInfo;

      // Get user info if connected
      if (session.isConnected && client && !userInfo) {
        try {
          userInfo = await client.getMe();
          session.userInfo = userInfo;
        } catch (error) {
          logger.error(`Failed to get user info for ${userId}:`, error);
        }
      }

      return {
        isConnected: session.isConnected,
        status: session.status,
        lastActivity: session.lastActivity,
        userInfo: userInfo,
        disconnectReason: session.disconnectReason,
        needsQR: session.status === 'waiting_qr'
      };
    } catch (error) {
      logger.error(`Failed to get status for user ${userId}:`, error);
      return {
        isConnected: false,
        status: 'error',
        error: error.message
      };
    }
  }

  async validatePhoneNumber(phoneNumber) {
    // Remove all non-digit characters
    const cleaned = phoneNumber.replace(/\D/g, '');
    
    // Validate length
    if (cleaned.length < 10 || cleaned.length > 15) {
      return { isValid: false, message: 'Nomor telepon harus 10-15 digit' };
    }

    // Check if starts with country code (Indonesia specific)
    let formattedNumber = cleaned;
    if (cleaned.startsWith('0')) {
      formattedNumber = '62' + cleaned.substring(1);
    } else if (!cleaned.startsWith('62')) {
      formattedNumber = '62' + cleaned;
    }

    return {
      isValid: true,
      formatted: `${formattedNumber}@c.us`,
      original: phoneNumber,
      cleaned: formattedNumber
    };
  }

  async sendMessage(userId, phoneNumber, message, mediaUrl = null) {
    try {
      const session = this.sessions.get(userId);
      if (!session || !session.isConnected) {
        throw new Error('WhatsApp tidak terhubung');
      }

      const client = session.client;
      
      // Validate phone number
      const validation = await this.validatePhoneNumber(phoneNumber);
      if (!validation.isValid) {
        throw new Error(validation.message);
      }

      // Prepare message
      let chatId = validation.formatted;
      
      // Check if contact exists
      try {
        const contact = await client.getContactById(chatId);
        if (!contact) {
          throw new Error('Kontak tidak ditemukan di WhatsApp');
        }
      } catch (error) {
        throw new Error(`Kontak ${phoneNumber} tidak valid atau tidak terdaftar di WhatsApp`);
      }

      let result;
      
      // Send media if provided
      if (mediaUrl) {
        const media = await MessageMedia.fromUrl(mediaUrl, {
          unsafeMime: true
        });
        
        result = await client.sendMessage(chatId, media, {
          caption: message
        });
      } else {
        result = await client.sendMessage(chatId, message);
      }

      // Update last activity
      session.lastActivity = Date.now();

      return {
        success: true,
        messageId: result.id.id,
        timestamp: result.timestamp,
        to: phoneNumber,
        status: 'sent'
      };
    } catch (error) {
      logger.error(`Failed to send message for user ${userId}:`, error);
      return {
        success: false,
        to: phoneNumber,
        error: error.message,
        status: 'failed'
      };
    }
  }

  async sendBroadcast(userId, broadcast) {
    const results = [];
    const batchSize = 10; // Send 10 messages at a time
    const delayBetweenBatches = 2000; // 2 seconds between batches
    
    try {
      const session = this.sessions.get(userId);
      if (!session || !session.isConnected) {
        throw new Error('WhatsApp tidak terhubung');
      }

      const client = session.client;
      const totalRecipients = broadcast.recipients.length;
      
      logger.info(`Starting broadcast for user ${userId} to ${totalRecipients} recipients`);

      // Process recipients in batches
      for (let i = 0; i < totalRecipients; i += batchSize) {
        const batch = broadcast.recipients.slice(i, i + batchSize);
        const batchPromises = [];

        for (const recipient of batch) {
          batchPromises.push(
            this.sendMessage(
              userId, 
              recipient, 
              broadcast.message, 
              broadcast.mediaUrl
            ).then(result => {
              results.push(result);
              return result;
            })
          );
        }

        // Wait for current batch to complete
        await Promise.allSettled(batchPromises);
        
        // Update progress (if you have a progress tracking system)
        const progress = Math.round(((i + batch.length) / totalRecipients) * 100);
        this.emit('broadcast_progress', userId, broadcast.id, progress);
        
        // Delay before next batch (to avoid rate limiting)
        if (i + batchSize < totalRecipients) {
          await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
        }
      }

      const successCount = results.filter(r => r.success).length;
      const failedCount = results.filter(r => !r.success).length;

      logger.info(`Broadcast completed for user ${userId}: ${successCount} success, ${failedCount} failed`);

      return {
        success: true,
        total: totalRecipients,
        sent: successCount,
        failed: failedCount,
        results: results,
        broadcastId: broadcast.id
      };
    } catch (error) {
      logger.error(`Broadcast failed for user ${userId}:`, error);
      
      return {
        success: false,
        total: broadcast.recipients.length,
        sent: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length,
        error: error.message,
        results: results
      };
    }
  }

  async getContacts(userId) {
    try {
      const session = this.sessions.get(userId);
      if (!session || !session.isConnected) {
        throw new Error('WhatsApp tidak terhubung');
      }

      const client = session.client;
      const contacts = await client.getContacts();
      
      // Filter and format contacts
      const formattedContacts = contacts
        .filter(contact => contact.isUser && contact.id.user)
        .map(contact => ({
          id: contact.id._serialized,
          name: contact.name || contact.pushname || 'Unknown',
          phone: contact.id.user,
          isBusiness: contact.isBusiness || false,
          isMyContact: contact.isMyContact || false
        }));

      return {
        success: true,
        contacts: formattedContacts,
        total: formattedContacts.length
      };
    } catch (error) {
      logger.error(`Failed to get contacts for user ${userId}:`, error);
      throw new Error(`Gagal mengambil kontak: ${error.message}`);
    }
  }

  async getChats(userId, limit = 50) {
    try {
      const session = this.sessions.get(userId);
      if (!session || !session.isConnected) {
        throw new Error('WhatsApp tidak terhubung');
      }

      const client = session.client;
      const chats = await client.getChats();
      
      // Sort by timestamp (most recent first) and limit
      const sortedChats = chats
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, limit)
        .map(chat => ({
          id: chat.id._serialized,
          name: chat.name,
          isGroup: chat.isGroup,
          isReadOnly: chat.isReadOnly,
          unreadCount: chat.unreadCount,
          timestamp: chat.timestamp,
          lastMessage: chat.lastMessage ? {
            body: chat.lastMessage.body,
            type: chat.lastMessage.type,
            from: chat.lastMessage.from,
            timestamp: chat.lastMessage.timestamp
          } : null
        }));

      return {
        success: true,
        chats: sortedChats,
        total: chats.length
      };
    } catch (error) {
      logger.error(`Failed to get chats for user ${userId}:`, error);
      throw new Error(`Gagal mengambil chat: ${error.message}`);
    }
  }

  async logout(userId) {
    try {
      const session = this.sessions.get(userId);
      if (session && session.client) {
        // Logout from WhatsApp Web
        await session.client.logout();
      }

      // Delete session files
      const sessionsDir = path.join(__dirname, '../sessions');
      const userSessionDir = path.join(sessionsDir, `user_${userId}`);
      
      try {
        await fs.rm(userSessionDir, { recursive: true, force: true });
      } catch (fsError) {
        logger.warn(`Could not delete session files for user ${userId}:`, fsError);
      }

      // Cleanup in-memory data
      this.clients.delete(userId);
      this.sessions.delete(userId);
      this.qrCodes.delete(userId);

      logger.info(`User ${userId} logged out from WhatsApp`);
      return { success: true };
    } catch (error) {
      logger.error(`Failed to logout user ${userId} from WhatsApp:`, error);
      throw new Error(`Gagal logout: ${error.message}`);
    }
  }

  // Health check for all active clients
  async healthCheck() {
    const status = {
      totalClients: this.clients.size,
      connectedClients: 0,
      disconnectedClients: 0,
      clients: []
    };

    for (const [userId, client] of this.clients) {
      const session = this.sessions.get(userId);
      const clientStatus = {
        userId,
        isConnected: session?.isConnected || false,
        status: session?.status || 'unknown',
        lastActivity: session?.lastActivity || null
      };

      if (clientStatus.isConnected) {
        status.connectedClients++;
      } else {
        status.disconnectedClients++;
      }

      status.clients.push(clientStatus);
    }

    return status;
  }
}

// Create singleton instance
const whatsappManager = new WhatsAppManager();

module.exports = whatsappManager;
