const database = require('./database');
const whatsappPairing = require('./pairing');

class BroadcastScheduler {
  constructor() {
    this.timers = new Map();
    this.init();
  }

  async init() {
    // Load scheduled broadcasts from database
    const scheduledBroadcasts = database.data.broadcasts.filter(
      b => b.status === 'scheduled' && b.scheduledFor
    );

    for (const broadcast of scheduledBroadcasts) {
      this.scheduleBroadcast(broadcast);
    }
  }

  scheduleBroadcast(broadcast) {
    const scheduledTime = new Date(broadcast.scheduledFor);
    const now = new Date();

    if (scheduledTime <= now) {
      // Send immediately if scheduled time has passed
      this.sendScheduledBroadcast(broadcast);
      return;
    }

    const delay = scheduledTime.getTime() - now.getTime();

    const timer = setTimeout(async () => {
      await this.sendScheduledBroadcast(broadcast);
    }, delay);

    this.timers.set(broadcast.id, timer);
  }

  async sendScheduledBroadcast(broadcast) {
    try {
      // Update status to processing
      await database.updateBroadcast(broadcast.id, {
        status: 'processing',
        processingStartedAt: new Date().toISOString()
      });

      // Check WhatsApp connection
      const isConnected = await whatsappPairing.checkConnection(broadcast.userId);
      if (!isConnected) {
        throw new Error('WhatsApp connection is not active');
      }

      // Send broadcast
      const results = await whatsappPairing.sendBroadcast(
        broadcast.userId,
        broadcast.contacts,
        broadcast.message
      );

      // Update broadcast stats
      const sentCount = results.filter(r => r.status === 'success').length;
      const failedCount = results.filter(r => r.status === 'failed').length;

      await database.updateBroadcast(broadcast.id, {
        status: sentCount > 0 ? 'sent' : 'failed',
        sentCount: sentCount,
        failedCount: failedCount,
        lastSentAt: new Date().toISOString(),
        results: results
      });

      // Remove timer
      this.timers.delete(broadcast.id);

    } catch (error) {
      console.error(`Error sending scheduled broadcast ${broadcast.id}:`, error);
      
      await database.updateBroadcast(broadcast.id, {
        status: 'failed',
        error: error.message,
        lastAttempt: new Date().toISOString()
      });
    }
  }

  cancelSchedule(broadcastId) {
    const timer = this.timers.get(broadcastId);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(broadcastId);
    }
  }

  reschedule(broadcast) {
    this.cancelSchedule(broadcast.id);
    this.scheduleBroadcast(broadcast);
  }
}

module.exports = new BroadcastScheduler();
