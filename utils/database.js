const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '../db.json');

class Database {
  constructor() {
    this.data = {
      users: [],
      broadcasts: [],
      sessions: [],
      pairing_codes: []
    };
    this.init();
  }

  async init() {
    try {
      const exists = await fs.access(DB_PATH).then(() => true).catch(() => false);
      if (!exists) {
        await this.save();
      } else {
        await this.load();
      }
    } catch (error) {
      console.error('Database initialization error:', error);
    }
  }

  async load() {
    try {
      const content = await fs.readFile(DB_PATH, 'utf8');
      this.data = JSON.parse(content);
    } catch (error) {
      console.error('Error loading database:', error);
    }
  }

  async save() {
    try {
      await fs.writeFile(DB_PATH, JSON.stringify(this.data, null, 2));
    } catch (error) {
      console.error('Error saving database:', error);
    }
  }

  // User operations
  async createUser(username, password, email) {
    const existingUser = this.data.users.find(u => u.username === username || u.email === email);
    if (existingUser) {
      throw new Error('Username atau email sudah terdaftar');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = {
      id: Date.now().toString(),
      username,
      email,
      password: hashedPassword,
      isVerified: false,
      pairingCode: null,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      isActive: true
    };

    this.data.users.push(user);
    await this.save();
    return user;
  }

  async findUser(username) {
    return this.data.users.find(u => u.username === username && u.isActive);
  }

  async findUserById(id) {
    return this.data.users.find(u => u.id === id && u.isActive);
  }

  async verifyPassword(user, password) {
    return await bcrypt.compare(password, user.password);
  }

  async updateUser(id, updates) {
    const index = this.data.users.findIndex(u => u.id === id);
    if (index !== -1) {
      this.data.users[index] = { ...this.data.users[index], ...updates };
      await this.save();
      return this.data.users[index];
    }
    return null;
  }

  // Pairing code operations
  async createPairingCode(userId) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const pairingCode = {
      code,
      userId,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(), // 10 menit
      isUsed: false,
      createdAt: new Date().toISOString()
    };

    this.data.pairing_codes.push(pairingCode);
    await this.save();
    return code;
  }

  async validatePairingCode(code, userId) {
    const pairingCode = this.data.pairing_codes.find(pc => 
      pc.code === code && 
      pc.userId === userId &&
      !pc.isUsed &&
      new Date(pc.expiresAt) > new Date()
    );

    if (pairingCode) {
      pairingCode.isUsed = true;
      await this.save();
      return true;
    }
    return false;
  }

  // Session operations
  async createSession(userId, sessionId) {
    const session = {
      sessionId,
      userId,
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString(),
      ipAddress: null,
      userAgent: null,
      isValid: true
    };

    this.data.sessions.push(session);
    await this.save();
    return session;
  }

  async validateSession(sessionId) {
    const session = this.data.sessions.find(s => 
      s.sessionId === sessionId && 
      s.isValid
    );

    if (session) {
      session.lastActive = new Date().toISOString();
      await this.save();
      return session;
    }
    return null;
  }

  async invalidateSession(sessionId) {
    const session = this.data.sessions.find(s => s.sessionId === sessionId);
    if (session) {
      session.isValid = false;
      await this.save();
    }
  }

  // Broadcast operations
  async createBroadcast(userId, data) {
    const broadcast = {
      id: Date.now().toString(),
      userId,
      ...data,
      status: 'pending',
      sentCount: 0,
      failedCount: 0,
      createdAt: new Date().toISOString(),
      scheduledFor: data.scheduledFor || null
    };

    this.data.broadcasts.push(broadcast);
    await this.save();
    return broadcast;
  }

  async getUserBroadcasts(userId) {
    return this.data.broadcasts.filter(b => b.userId === userId);
  }

  async updateBroadcast(id, updates) {
    const index = this.data.broadcasts.findIndex(b => b.id === id);
    if (index !== -1) {
      this.data.broadcasts[index] = { ...this.data.broadcasts[index], ...updates };
      await this.save();
      return this.data.broadcasts[index];
    }
    return null;
  }
}

module.exports = new Database();
