const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');

class DatabaseBackup {
  constructor() {
    this.backupDir = path.join(__dirname, '../backups');
    this.dbPath = path.join(__dirname, '../db.json');
  }

  async init() {
    try {
      await fs.mkdir(this.backupDir, { recursive: true });
    } catch (error) {
      console.error('Error creating backup directory:', error);
    }
  }

  async createBackup() {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath = path.join(this.backupDir, `backup-${timestamp}.json`);
      
      // Read current database
      const data = await fs.readFile(this.dbPath, 'utf8');
      
      // Write backup
      await fs.writeFile(backupPath, data);
      
      console.log(`Backup created: ${backupPath}`);
      
      // Cleanup old backups (keep last 7 days)
      await this.cleanupOldBackups();
      
      return backupPath;
    } catch (error) {
      console.error('Error creating backup:', error);
      throw error;
    }
  }

  async cleanupOldBackups() {
    try {
      const files = await fs.readdir(this.backupDir);
      const now = Date.now();
      const sevenDaysAgo = now - (7 * 24 * 60 * 60 * 1000);

      for (const file of files) {
        if (file.startsWith('backup-')) {
          const filePath = path.join(this.backupDir, file);
          const stats = await fs.stat(filePath);
          
          if (stats.mtimeMs < sevenDaysAgo) {
            await fs.unlink(filePath);
            console.log(`Deleted old backup: ${file}`);
          }
        }
      }
    } catch (error) {
      console.error('Error cleaning up old backups:', error);
    }
  }

  async restoreBackup(backupFile) {
    try {
      const backupPath = path.join(this.backupDir, backupFile);
      
      // Check if backup exists
      await fs.access(backupPath);
      
      // Read backup
      const data = await fs.readFile(backupPath, 'utf8');
      
      // Write to current database
      await fs.writeFile(this.dbPath, data);
      
      console.log(`Backup restored: ${backupFile}`);
      
      return true;
    } catch (error) {
      console.error('Error restoring backup:', error);
      throw error;
    }
  }

  async listBackups() {
    try {
      const files = await fs.readdir(this.backupDir);
      const backups = [];
      
      for (const file of files) {
        if (file.startsWith('backup-')) {
          const filePath = path.join(this.backupDir, file);
          const stats = await fs.stat(filePath);
          backups.push({
            name: file,
            size: stats.size,
            modified: stats.mtime,
            path: filePath
          });
        }
      }
      
      // Sort by date (newest first)
      backups.sort((a, b) => b.modified - a.modified);
      
      return backups;
    } catch (error) {
      console.error('Error listing backups:', error);
      return [];
    }
  }
}

// Auto backup every 6 hours
const backupManager = new DatabaseBackup();
backupManager.init().then(() => {
  setInterval(() => {
    backupManager.createBackup().catch(console.error);
  }, 6 * 60 * 60 * 1000);
});

module.exports = backupManager;
