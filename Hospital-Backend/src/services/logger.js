/**
 * Centralized Logging Service for Healthcare Application
 * 
 * This module provides unified logging capabilities across all services:
 * - IAM (Identity & Access Management)
 * - MFA (Multi-Factor Authentication)
 * - Encryption/Decryption
 * - API Gateway
 * - Lab Module, Pharmacy, Billing, etc.
 * 
 * Features:
 * - Standard log format (timestamp, service, event, user, severity, details, IP)
 * - Separation of Audit Logs and Application Logs
 * - Sensitive data sanitization
 * - Real-time metrics tracking
 * - Database persistence for audit logs
 */

const db = require('../db');

// Log severity levels
const SEVERITY = {
  DEBUG: 'DEBUG',
  INFO: 'INFO',
  WARN: 'WARN',
  ERROR: 'ERROR',
  CRITICAL: 'CRITICAL'
};

// Event categories
const CATEGORY = {
  AUDIT: 'AUDIT',       // Security-related events
  APPLICATION: 'APP'     // Normal application events
};

// Service identifiers
const SERVICE = {
  IAM: 'IAM',
  MFA: 'MFA',
  ENCRYPTION: 'ENCRYPTION',
  API: 'API',
  LAB: 'LAB',
  PHARMACY: 'PHARMACY',
  BILLING: 'BILLING',
  PATIENT: 'PATIENT',
  APPOINTMENT: 'APPOINTMENT',
  SYSTEM: 'SYSTEM'
};

// Event types for Audit Logs
const AUDIT_EVENTS = {
  // IAM Events
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  PASSWORD_RESET: 'PASSWORD_RESET',
  ROLE_CHANGE: 'ROLE_CHANGE',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
  
  // MFA Events
  MFA_ENABLED: 'MFA_ENABLED',
  MFA_DISABLED: 'MFA_DISABLED',
  MFA_SUCCESS: 'MFA_SUCCESS',
  MFA_FAILURE: 'MFA_FAILURE',
  MFA_BRUTE_FORCE: 'MFA_BRUTE_FORCE',
  
  // Encryption Events
  FILE_ENCRYPTED: 'FILE_ENCRYPTED',
  FILE_DECRYPTED: 'FILE_DECRYPTED',
  DECRYPT_DENIED: 'DECRYPT_DENIED',
  KEY_ROTATION: 'KEY_ROTATION',

  // File Upload/Download Events
  FILE_UPLOADED: 'FILE_UPLOADED',
  FILE_DOWNLOADED: 'FILE_DOWNLOADED',
  FILE_DELETED: 'FILE_DELETED',
  FILE_ACCESS_DENIED: 'FILE_ACCESS_DENIED',
  
  // Data Access Events
  PATIENT_VIEW: 'PATIENT_VIEW',
  PATIENT_CREATE: 'PATIENT_CREATE',
  PATIENT_UPDATE: 'PATIENT_UPDATE',
  PATIENT_DELETE: 'PATIENT_DELETE',
  LAB_RESULT_VIEW: 'LAB_RESULT_VIEW',
  PRESCRIPTION_VIEW: 'PRESCRIPTION_VIEW',
  BILLING_ACCESS: 'BILLING_ACCESS'
};

// In-memory metrics counters
const metrics = {
  totalLogs: 0,
  auditLogs: 0,
  applicationLogs: 0,
  errorCount: 0,
  loginFailures: 0,
  mfaFailures: 0,
  decryptAttempts: 0,
  decryptFailures: 0,
  unauthorizedAccess: 0,
  byService: {},
  bySeverity: {},
  startTime: new Date()
};

// Sensitive fields to mask in logs
const SENSITIVE_FIELDS = [
  'password', 'mfaSecret', 'token', 'refreshToken', 'apiKey',
  'ssn', 'creditCard', 'cvv', 'pin', 'otp', 'code',
  'encryptionKey', 'privateKey', 'secret'
];

/**
 * Mask sensitive data in log details
 */
function sanitizeData(data) {
  if (!data || typeof data !== 'object') return data;
  
  const sanitized = { ...data };
  for (const key of Object.keys(sanitized)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_FIELDS.some(field => lowerKey.includes(field.toLowerCase()))) {
      sanitized[key] = '***REDACTED***';
    } else if (typeof sanitized[key] === 'object') {
      sanitized[key] = sanitizeData(sanitized[key]);
    }
  }
  return sanitized;
}

/**
 * Create standardized log entry
 */
function createLogEntry(options) {
  const {
    service,
    eventType,
    userId = null,
    userEmail = null,
    userRole = null,
    severity = SEVERITY.INFO,
    category = CATEGORY.APPLICATION,
    details = {},
    ipAddress = null,
    userAgent = null,
    resourceId = null,
    resourceType = null,
    status = 'success'
  } = options;

  return {
    timestamp: new Date().toISOString(),
    service,
    eventType,
    userId,
    userEmail,
    userRole,
    severity,
    category,
    details: sanitizeData(details),
    ipAddress,
    userAgent,
    resourceId,
    resourceType,
    status
  };
}

/**
 * Update metrics based on log entry
 */
function updateMetrics(entry) {
  metrics.totalLogs++;

  if (entry.category === CATEGORY.AUDIT) {
    metrics.auditLogs++;
  } else {
    metrics.applicationLogs++;
  }

  // Track by severity
  metrics.bySeverity[entry.severity] = (metrics.bySeverity[entry.severity] || 0) + 1;

  // Track by service
  metrics.byService[entry.service] = (metrics.byService[entry.service] || 0) + 1;

  // Track specific security metrics
  if (entry.severity === SEVERITY.ERROR || entry.severity === SEVERITY.CRITICAL) {
    metrics.errorCount++;
  }

  switch (entry.eventType) {
    case AUDIT_EVENTS.LOGIN_FAILURE:
      metrics.loginFailures++;
      break;
    case AUDIT_EVENTS.MFA_FAILURE:
    case AUDIT_EVENTS.MFA_BRUTE_FORCE:
      metrics.mfaFailures++;
      break;
    case AUDIT_EVENTS.FILE_DECRYPTED:
      metrics.decryptAttempts++;
      break;
    case AUDIT_EVENTS.DECRYPT_DENIED:
      metrics.decryptAttempts++;
      metrics.decryptFailures++;
      break;
    case AUDIT_EVENTS.UNAUTHORIZED_ACCESS:
    case AUDIT_EVENTS.PERMISSION_DENIED:
      metrics.unauthorizedAccess++;
      break;
  }
}

/**
 * Write log to console (development)
 */
function writeToConsole(entry) {
  const severityColors = {
    DEBUG: '\x1b[36m',    // Cyan
    INFO: '\x1b[32m',     // Green
    WARN: '\x1b[33m',     // Yellow
    ERROR: '\x1b[31m',    // Red
    CRITICAL: '\x1b[35m'  // Magenta
  };
  const reset = '\x1b[0m';
  const color = severityColors[entry.severity] || reset;

  const logLine = `${color}[${entry.timestamp}] [${entry.severity}] [${entry.service}] ${entry.eventType}${reset}`;
  const details = entry.userId ? ` | User: ${entry.userEmail || entry.userId}` : '';
  const ip = entry.ipAddress ? ` | IP: ${entry.ipAddress}` : '';

  console.log(`${logLine}${details}${ip}`);

  if (entry.severity === SEVERITY.ERROR || entry.severity === SEVERITY.CRITICAL) {
    console.log(`  Details: ${JSON.stringify(entry.details)}`);
  }
}

/**
 * Persist audit log to database
 */
async function persistAuditLog(entry) {
  try {
    await db.query(
      `INSERT INTO audit_logs
       (actor_id, action, resource_type, resource_id, remote_addr, user_agent, details, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        entry.userId || null,
        `${entry.service}:${entry.eventType}`,
        entry.resourceType || 'system',
        entry.resourceId || null,
        entry.ipAddress || null,
        entry.userAgent || null,
        JSON.stringify({
          severity: entry.severity,
          userEmail: entry.userEmail,
          userRole: entry.userRole,
          ...entry.details
        }),
        entry.status || 'success',
        entry.timestamp
      ]
    );
  } catch (error) {
    console.error('Failed to persist audit log:', error.message);
  }
}

/**
 * Main logging function
 */
async function log(options) {
  const entry = createLogEntry(options);

  // Update metrics
  updateMetrics(entry);

  // Write to console in development
  if (process.env.NODE_ENV !== 'production' || options.severity === SEVERITY.ERROR) {
    writeToConsole(entry);
  }

  // Persist audit logs to database
  if (entry.category === CATEGORY.AUDIT) {
    await persistAuditLog(entry);
  }

  return entry;
}

// ============ Convenience logging functions ============

/**
 * Log IAM events (login, logout, role changes)
 */
async function logIAM(eventType, options) {
  return log({
    service: SERVICE.IAM,
    eventType,
    category: CATEGORY.AUDIT,
    ...options
  });
}

/**
 * Log MFA events (verification, failures)
 */
async function logMFA(eventType, options) {
  return log({
    service: SERVICE.MFA,
    eventType,
    category: CATEGORY.AUDIT,
    ...options
  });
}

/**
 * Log Encryption events (encrypt, decrypt)
 */
async function logEncryption(eventType, options) {
  return log({
    service: SERVICE.ENCRYPTION,
    eventType,
    category: CATEGORY.AUDIT,
    ...options
  });
}

/**
 * Log API events (requests, errors)
 */
async function logAPI(eventType, options) {
  return log({
    service: SERVICE.API,
    eventType,
    category: CATEGORY.APPLICATION,
    ...options
  });
}

/**
 * Log patient data access
 */
async function logPatientAccess(eventType, options) {
  return log({
    service: SERVICE.PATIENT,
    eventType,
    category: CATEGORY.AUDIT,
    resourceType: 'patient',
    ...options
  });
}

/**
 * Get current metrics
 */
function getMetrics() {
  const uptime = Math.floor((new Date() - metrics.startTime) / 1000);
  return {
    ...metrics,
    uptime,
    uptimeFormatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${uptime % 60}s`
  };
}

/**
 * Reset metrics (for testing)
 */
function resetMetrics() {
  metrics.totalLogs = 0;
  metrics.auditLogs = 0;
  metrics.applicationLogs = 0;
  metrics.errorCount = 0;
  metrics.loginFailures = 0;
  metrics.mfaFailures = 0;
  metrics.decryptAttempts = 0;
  metrics.decryptFailures = 0;
  metrics.unauthorizedAccess = 0;
  metrics.byService = {};
  metrics.bySeverity = {};
  metrics.startTime = new Date();
}

module.exports = {
  log,
  logIAM,
  logMFA,
  logEncryption,
  logAPI,
  logPatientAccess,
  getMetrics,
  resetMetrics,
  SEVERITY,
  CATEGORY,
  SERVICE,
  AUDIT_EVENTS
};

