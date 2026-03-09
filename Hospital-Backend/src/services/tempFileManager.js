/**
 * Temp File Manager
 * Manages temporary files created during decryption
 * Auto-cleans files when user session ends or timeout occurs
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Store active session temp directories
const activeSessions = new Map(); // userId -> { tempDir, createdAt, sessionId }

// Cleanup timeout: 30 minutes of inactivity (or 5 minutes for testing/development)
const CLEANUP_TIMEOUT = process.env.TEMP_CLEANUP_TIMEOUT 
  ? parseInt(process.env.TEMP_CLEANUP_TIMEOUT) * 60 * 1000
  : 30 * 60 * 1000; // Default: 30 minutes

// Base temp directory
const TEMP_BASE = path.join(process.cwd(), '.temp-decrypted');

/**
 * Initialize session temp directory
 */
async function initSessionTempDir(userId, sessionId) {
  try {
    // Create temp directory if it doesn't exist
    await fs.mkdir(TEMP_BASE, { recursive: true });

    // Create user-specific directory
    const sessionDir = path.join(TEMP_BASE, `${userId}-${sessionId}`);
    await fs.mkdir(sessionDir, { recursive: true });

    console.log(`✓ Created temp dir for user ${userId}: ${sessionDir}`);

    // Store session info
    activeSessions.set(`${userId}:${sessionId}`, {
      tempDir: sessionDir,
      createdAt: Date.now(),
      userId,
      sessionId,
      fileCount: 0,
      lastAccessed: Date.now()
    });

    // Set cleanup timeout
    scheduleSessionCleanup(userId, sessionId);

    return sessionDir;
  } catch (err) {
    console.error('Error initializing temp directory:', err);
    throw err;
  }
}

/**
 * Get or create temp directory for user
 */
async function getTempDir(userId, sessionId) {
  const key = `${userId}:${sessionId}`;
  const session = activeSessions.get(key);

  if (session) {
    // Update last accessed time
    session.lastAccessed = Date.now();
    return session.tempDir;
  }

  // Create new session
  return initSessionTempDir(userId, sessionId);
}

/**
 * Save decrypted file to temp directory
 */
async function saveTempFile(userId, sessionId, filename, content) {
  try {
    const tempDir = await getTempDir(userId, sessionId);
    const filepath = path.join(tempDir, filename);

    // Ensure content is a Buffer
    const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content);

    await fs.writeFile(filepath, buffer);

    // Update file count
    const key = `${userId}:${sessionId}`;
    const session = activeSessions.get(key);
    if (session) {
      session.fileCount++;
    }

    console.log(`✓ Saved temp file: ${filename} (${buffer.length} bytes)`);
    return filepath;
  } catch (err) {
    console.error('Error saving temp file:', err);
    throw err;
  }
}

/**
 * Read decrypted file from temp directory
 */
async function readTempFile(userId, sessionId, filename) {
  try {
    const tempDir = await getTempDir(userId, sessionId);
    const filepath = path.join(tempDir, filename);

    // Verify file is within temp directory (security check)
    const realpath = await fs.realpath(filepath).catch(() => null);
    if (!realpath || !realpath.startsWith(await fs.realpath(tempDir))) {
      throw new Error('Invalid file path');
    }

    const content = await fs.readFile(filepath);
    console.log(`✓ Read temp file: ${filename}`);
    return content;
  } catch (err) {
    console.error('Error reading temp file:', err);
    throw err;
  }
}

/**
 * Clean up all files for a session
 */
async function cleanupSession(userId, sessionId) {
  const key = `${userId}:${sessionId}`;
  const session = activeSessions.get(key);

  if (!session) return;

  try {
    // Remove directory and all contents
    await fs.rm(session.tempDir, { recursive: true, force: true });
    console.log(`✓ Cleaned up temp directory for ${userId} (${sessionId})`);
  } catch (err) {
    console.error(`Error cleaning up temp directory: ${err.message}`);
  }

  // Remove from active sessions
  activeSessions.delete(key);
}

/**
 * Clean up expired sessions (inactivity timeout)
 */
async function cleanupExpiredSessions() {
  const now = Date.now();
  const keysToDelete = [];

  for (const [key, session] of activeSessions.entries()) {
    const inactiveTime = now - session.lastAccessed;

    // If inactive for more than CLEANUP_TIMEOUT
    if (inactiveTime > CLEANUP_TIMEOUT) {
      keysToDelete.push({ key, session });
    }
  }

  for (const { key, session } of keysToDelete) {
    try {
      await fs.rm(session.tempDir, { recursive: true, force: true });
      console.log(`✓ Auto-cleaned expired session ${session.userId} (${Math.round(CLEANUP_TIMEOUT / 1000 / 60)} min timeout)`);
      activeSessions.delete(key);
    } catch (err) {
      console.error(`Error auto-cleaning session: ${err.message}`);
    }
  }
}

/**
 * Schedule automatic session cleanup
 */
function scheduleSessionCleanup(userId, sessionId) {
  const key = `${userId}:${sessionId}`;
  const session = activeSessions.get(key);

  if (!session) return;

  // Set timeout to cleanup after inactivity
  setTimeout(() => {
    const current = activeSessions.get(key);
    if (current && Date.now() - current.lastAccessed > CLEANUP_TIMEOUT) {
      cleanupSession(userId, sessionId).catch(err => {
        console.error('Scheduled cleanup error:', err);
      });
    }
  }, CLEANUP_TIMEOUT);
}

/**
 * Get session info for debugging
 */
function getSessionInfo(userId, sessionId) {
  const key = `${userId}:${sessionId}`;
  return activeSessions.get(key);
}

/**
 * List all active sessions
 */
function listActiveSessions() {
  const sessions = [];
  for (const [key, session] of activeSessions.entries()) {
    sessions.push({
      sessionKey: key,
      userId: session.userId,
      fileCount: session.fileCount,
      createdAt: new Date(session.createdAt),
      lastAccessed: new Date(session.lastAccessed),
      inactiveTime: `${Math.round((Date.now() - session.lastAccessed) / 1000 / 60)} min`
    });
  }
  return sessions;
}

/**
 * Initialize cleanup job (runs every 10 minutes, or configurable interval)
 */
function startCleanupJob() {
  const cleanupIntervalMinutes = process.env.TEMP_CLEANUP_INTERVAL || 10;
  const intervalMs = cleanupIntervalMinutes * 60 * 1000;
  
  setInterval(() => {
    cleanupExpiredSessions().catch(err => {
      console.error('Cleanup job error:', err);
    });
  }, intervalMs);

  console.log(`✓ Temp file cleanup job started (checks every ${cleanupIntervalMinutes} min, timeout: ${Math.round(CLEANUP_TIMEOUT / 1000 / 60)} min)`);
}

module.exports = {
  initSessionTempDir,
  getTempDir,
  saveTempFile,
  readTempFile,
  cleanupSession,
  cleanupExpiredSessions,
  getSessionInfo,
  listActiveSessions,
  startCleanupJob,
  CLEANUP_TIMEOUT,
  TEMP_BASE
};
