const QRCode = require('qrcode');
const { WAConnection } = require('@adiwajshing/baileys');

class WhatsAppPairing {
  constructor() {
    this.connections = new Map();
  }

  async createConnection(userId) {
    const conn = new WAConnection();
    
    // Event handlers
    conn.on('qr', (qr) => {
      this.connections.set(userId, { conn, qr });
    });

    conn.on('open', () => {
      const userConn = this.connections.get(userId);
      if (userConn) {
        userConn.qr = null;
        userConn.isConnected = true;
      }
    });

    conn.on('close', () => {
      this.connections.delete(userId);
    });

    await conn.connect();
    return conn;
  }

  async getQRCode(userId) {
    const userConn = this.connections.get(userId);
    if (!userConn || !userConn.qr) {
      throw new Error('QR code tidak tersedia');
    }

    return await QRCode.toDataURL(userConn.qr);
  }

  async checkConnection(userId) {
    const userConn = this.connections.get(userId);
    return userConn && userConn.isConnected;
  }

  async disconnect(userId) {
    const userConn = this.connections.get(userId);
    if (userConn && userConn.conn) {
      await userConn.conn.close();
    }
    this.connections.delete(userId);
  }

  async sendBroadcast(userId, contacts, message) {
    const userConn = this.connections.get(userId);
    if (!userConn || !userConn.isConnected) {
      throw new Error('Koneksi WhatsApp tidak aktif');
    }

    const results = [];
    for (const contact of contacts) {
      try {
        const id = `${contact}@s.whatsapp.net`;
        await userConn.conn.sendMessage(id, message, MessageType.text);
        results.push({ contact, status: 'success' });
      } catch (error) {
        results.push({ contact, status: 'failed', error: error.message });
      }
    }

    return results;
  }
}

module.exports = new WhatsAppPairing();
