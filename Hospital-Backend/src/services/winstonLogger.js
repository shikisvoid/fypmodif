/**
 * Winston-based Comprehensive Logging Service
 * 
 * Provides structured JSON logging with separate log files:
 * - /logs/security.log - Authentication, authorization events
 * - /logs/access.log - Medical data access events
 * - /logs/encryption.log - Encryption/decryption operations
 * - /logs/storage.log - File upload/download/delete
 * - /logs/error.log - Errors and exceptions
 * - /logs/audit.log - Data modification events
 * - /logs/api.log - API requests and responses
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom JSON format for structured logging
const jsonFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, service, eventType, ...meta }) => {
    const svc = service ? `[${service}]` : '';
    const evt = eventType ? `[${eventType}]` : '';
    return `${timestamp} ${level} ${svc}${evt} ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
  })
);

// Create transports for each log type
const createFileTransport = (filename) => new winston.transports.File({
  filename: path.join(logsDir, filename),
  format: jsonFormat,
  maxsize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5,
  tailable: true
});

// Main loggers for different categories
const securityLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'security' },
  transports: [
    createFileTransport('security.log'),
    new winston.transports.Console({ format: consoleFormat, level: 'warn' })
  ]
});

const accessLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'access' },
  transports: [
    createFileTransport('access.log'),
    new winston.transports.Console({ format: consoleFormat, level: 'debug' })
  ]
});

const encryptionLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'encryption' },
  transports: [
    createFileTransport('encryption.log'),
    new winston.transports.Console({ format: consoleFormat, level: 'warn' })
  ]
});

const storageLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'storage' },
  transports: [
    createFileTransport('storage.log'),
    new winston.transports.Console({ format: consoleFormat, level: 'info' })
  ]
});

const errorLogger = winston.createLogger({
  level: 'error',
  defaultMeta: { service: 'error' },
  transports: [
    createFileTransport('error.log'),
    new winston.transports.Console({ format: consoleFormat })
  ]
});

const auditLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'audit' },
  transports: [
    createFileTransport('audit.log'),
    new winston.transports.Console({ format: consoleFormat, level: 'info' })
  ]
});

const apiLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'api' },
  transports: [
    createFileTransport('api.log'),
    new winston.transports.Console({ format: consoleFormat, level: 'debug' })
  ]
});

// Event types
const SECURITY_EVENTS = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  MFA_SENT: 'MFA_SENT',
  MFA_VERIFIED: 'MFA_VERIFIED',
  PASSWORD_RESET_REQUESTED: 'PASSWORD_RESET_REQUESTED',
  PASSWORD_RESET_COMPLETED: 'PASSWORD_RESET_COMPLETED',
  UNAUTHORIZED_ACCESS_ATTEMPT: 'UNAUTHORIZED_ACCESS_ATTEMPT',
  JWT_EXPIRED: 'JWT_EXPIRED',
  JWT_INVALID_SIGNATURE: 'JWT_INVALID_SIGNATURE',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  LOGOUT: 'LOGOUT'
};

const ACCESS_EVENTS = {
  PATIENT_RECORD_VIEWED: 'PATIENT_RECORD_VIEWED',
  FILE_DECRYPTED: 'FILE_DECRYPTED',
  FILE_DOWNLOADED: 'FILE_DOWNLOADED',
  LAB_RESULT_VIEWED: 'LAB_RESULT_VIEWED',
  PRESCRIPTION_VIEWED: 'PRESCRIPTION_VIEWED',
  BILLING_VIEWED: 'BILLING_VIEWED'
};

const ENCRYPTION_EVENTS = {
  FILE_ENCRYPTED: 'FILE_ENCRYPTED',
  FILE_DECRYPTED: 'FILE_DECRYPTED',
  FIELD_ENCRYPTED: 'FIELD_ENCRYPTED',
  FIELD_DECRYPTED: 'FIELD_DECRYPTED',
  KEY_ROTATION: 'KEY_ROTATION'
};

const STORAGE_EVENTS = {
  FILE_UPLOADED: 'FILE_UPLOADED',
  FILE_DELETED: 'FILE_DELETED',
  FILE_ENCRYPTED: 'FILE_ENCRYPTED',
  FILE_DOWNLOADED: 'FILE_DOWNLOADED'
};

const AUDIT_EVENTS = {
  PATIENT_CREATED: 'PATIENT_CREATED',
  PATIENT_UPDATED: 'PATIENT_UPDATED',
  PATIENT_DELETED: 'PATIENT_DELETED',
  LAB_TEST_CREATED: 'LAB_TEST_CREATED',
  LAB_TEST_UPDATED: 'LAB_TEST_UPDATED',
  PRESCRIPTION_CREATED: 'PRESCRIPTION_CREATED',
  PRESCRIPTION_UPDATED: 'PRESCRIPTION_UPDATED',
  BILLING_CREATED: 'BILLING_CREATED',
  BILLING_UPDATED: 'BILLING_UPDATED',
  APPOINTMENT_CREATED: 'APPOINTMENT_CREATED',
  APPOINTMENT_UPDATED: 'APPOINTMENT_UPDATED',
  APPOINTMENT_DELETED: 'APPOINTMENT_DELETED'
};

// ================== SECURITY LOGGING ==================
function logSecurity(eventType, data) {
  const entry = {
    eventType,
    userId: data.userId || null,
    role: data.role || null,
    ipAddress: data.ipAddress || null,
    userAgent: data.userAgent || null,
    email: data.email || null,
    ...data.details
  };

  if (eventType === SECURITY_EVENTS.LOGIN_FAILURE ||
      eventType === SECURITY_EVENTS.UNAUTHORIZED_ACCESS_ATTEMPT) {
    securityLogger.warn(eventType, entry);
  } else {
    securityLogger.info(eventType, entry);
  }
  return entry;
}

// ================== ACCESS LOGGING ==================
function logAccess(eventType, data) {
  const entry = {
    eventType,
    userId: data.userId,
    role: data.role,
    action: eventType,
    resourceId: data.resourceId,
    resourceType: data.resourceType,
    ipAddress: data.ipAddress,
    ...data.details
  };
  accessLogger.info(eventType, entry);
  return entry;
}

// ================== ENCRYPTION LOGGING ==================
function logEncryption(eventType, data) {
  const entry = {
    eventType,
    fileId: data.fileId || data.resourceId,
    algorithmUsed: data.algorithm || 'AES-256-GCM',
    keyId: data.keyId || 'master-key',
    performedByUserId: data.userId,
    ipAddress: data.ipAddress,
    status: data.status || 'success',
    ...data.details
  };

  if (data.status === 'failure') {
    encryptionLogger.error(eventType, entry);
    // Also log to error log for critical events
    errorLogger.error(`Encryption failure: ${eventType}`, entry);
  } else {
    encryptionLogger.info(eventType, entry);
  }
  return entry;
}

// ================== STORAGE LOGGING ==================
function logStorage(eventType, data) {
  const entry = {
    eventType,
    fileId: data.fileId,
    originalName: data.originalName,
    storedPath: data.storedPath,
    checksum: data.checksum || null,
    sha256: data.sha256 || null,
    encrypted: data.encrypted || false,
    fileSize: data.fileSize,
    performedByUserId: data.userId,
    ...data.details
  };
  storageLogger.info(eventType, entry);
  return entry;
}

// ================== AUDIT LOGGING (Data Modifications) ==================
const db = require('../db');

async function logAudit(eventType, data) {
  const entry = {
    eventType,
    resourceType: data.resourceType,
    resourceId: data.resourceId,
    oldValue: data.oldValue || null,
    newValue: data.newValue || null,
    changedByUserId: data.userId,
    changedByEmail: data.email,
    changedByRole: data.role,
    ipAddress: data.ipAddress
  };

  // Log to file
  auditLogger.info(eventType, entry);

  // Also persist to database audit_logs table
  try {
    await db.query(
      `INSERT INTO audit_logs
       (actor_id, action, resource_type, resource_id, remote_addr, user_agent, details, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
      [
        data.userId,
        eventType,
        data.resourceType,
        data.resourceId,
        data.ipAddress,
        data.userAgent,
        JSON.stringify({ oldValue: data.oldValue, newValue: data.newValue, ...data.details }),
        'success'
      ]
    );
  } catch (err) {
    errorLogger.error('Failed to persist audit log to database', { error: err.message, entry });
  }

  return entry;
}

// ================== ERROR LOGGING ==================
function logError(errorType, data) {
  const entry = {
    errorType,
    message: data.message || data.error?.message,
    stack: data.error?.stack,
    userId: data.userId,
    endpoint: data.endpoint,
    method: data.method,
    ipAddress: data.ipAddress,
    ...data.details
  };
  errorLogger.error(errorType, entry);
  return entry;
}

// ================== API LOGGING ==================
function logAPI(data) {
  const entry = {
    requestId: data.requestId || `req-${Date.now()}`,
    method: data.method,
    endpoint: data.endpoint,
    statusCode: data.statusCode,
    responseTime: data.responseTime,
    userId: data.userId || null,
    ipAddress: data.ipAddress,
    userAgent: data.userAgent
  };

  if (data.statusCode >= 400) {
    apiLogger.warn('API_ERROR', entry);
  } else {
    apiLogger.info('API_REQUEST', entry);
  }
  return entry;
}

module.exports = {
  // Loggers
  securityLogger, accessLogger, encryptionLogger,
  storageLogger, errorLogger, auditLogger, apiLogger,

  // Logging functions
  logSecurity, logAccess, logEncryption, logStorage, logAudit, logError, logAPI,

  // Event constants
  SECURITY_EVENTS, ACCESS_EVENTS, ENCRYPTION_EVENTS, STORAGE_EVENTS, AUDIT_EVENTS,

  // Logs directory
  logsDir
};

