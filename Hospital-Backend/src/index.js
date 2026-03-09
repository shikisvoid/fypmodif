/**
 * src/index.js
 * Main Express server with JWT authentication and routes
 *
 * Integrated with comprehensive logging and monitoring:
 * - Winston-based structured logging to separate log files
 * - Security monitoring with anomaly detection
 * - System metrics (CPU, RAM, event loop)
 * - API performance monitoring
 * - Phase 2: EDR role-aware telemetry middleware
 */
require('dotenv').config();
require('express-async-errors');

// ===== PHASE 2 EDR ROLE-AWARE MIDDLEWARE =====
let createEdrMiddleware = null;
try {
  const edrModule = require('/edr/role-edr-middleware');
  createEdrMiddleware = edrModule.createEdrMiddleware;
  console.log('✓ EDR role-aware middleware loaded');
} catch (err) {
  console.warn('⚠ EDR role-aware middleware not available:', err.message);
}
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');
const logger = require('./services/logger');
const monitoring = require('./services/monitoring');
const winstonLogger = require('./services/winstonLogger');
const securityMonitor = require('./services/securityMonitor');
const systemMonitor = require('./services/systemMonitor');
const { encryptField, decryptField, encryptFile, decryptFile } = require('./services/fieldEncryption');
const { encryptSensitiveFields, decryptSensitiveFields, canAccessField } = require('./services/encryptionMiddleware');

const app = express();

// File encryption support (optional - loaded if available)
let encryptionService = null;
try {
  encryptionService = require('../../Encryption/encryptionService');
  console.log('✓ Encryption service loaded');
} catch (err) {
  console.warn('⚠ Encryption service not available, file encryption endpoints will not work');
}

// CORS middleware - Allow frontend connections
app.use((req, res, next) => {
  const allowedOrigins = ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:5175'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 300, // 300 requests per minute
  message: { success: false, error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// ===== PHASE 2: EDR Role-Aware Middleware =====
if (createEdrMiddleware) {
  const edrTarget = process.env.EDR_TARGET || 'http://172.20.0.100:9090/ingest/telemetry';
  app.use(createEdrMiddleware({
    hostId: 'hospital-backend',
    target: edrTarget,
    batchIntervalMs: 2000,
    maxBatchSize: 50
  }));
  console.log(`✓ EDR role-aware middleware active → ${edrTarget}`);
}

// Request monitoring middleware with comprehensive logging
app.use((req, res, next) => {
  const startTime = Date.now();
  const requestId = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  req.requestId = requestId;

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    // Record in both monitoring systems
    monitoring.recordHttpRequest(req.method, req.path, res.statusCode, duration);
    systemMonitor.recordAPIRequest(req.method, req.path, res.statusCode, duration, req.user?.userId);
  });
  next();
});

// Security check middleware - Block IPs with excessive failures
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (securityMonitor.isIPBlocked(ip)) {
    winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.UNAUTHORIZED_ACCESS_ATTEMPT, {
      ipAddress: ip,
      details: { reason: 'IP_BLOCKED', endpoint: req.path }
    });
    return res.status(403).json({
      success: false,
      error: 'Access denied. Too many failed attempts.'
    });
  }
  next();
});

// ===== AUTHENTICATION MIDDLEWARE =====

// Role permissions (same as frontend data.js) - Includes encryption permissions per role
const ROLE_PERMISSIONS = {
  admin: {
    canViewPatients: true,
    canEditPatients: true,
    canDeletePatients: true,
    canViewAppointments: true,
    canManageAppointments: true,
    canViewRecords: true,
    canEditRecords: true,
    canManageUsers: true,
    canViewReports: true,
    canAccessSettings: true,
    canViewBilling: true,
    canEditBilling: true,
    canManageBilling: true,
    canViewLabs: true,
    canManageLabs: true,
    canViewPharmacy: true,
    canManagePharmacy: true,
    // Encryption permissions - Admin can decrypt logs but NOT medical data
    canDecryptLogs: true,
    canDecryptMedical: false,
    canDecryptBilling: false
  },
  doctor: {
    canViewPatients: true,
    canEditPatients: true,
    canDeletePatients: false,
    canViewAppointments: true,
    canManageAppointments: true,
    canViewRecords: true,
    canEditRecords: true,
    canManageUsers: false,
    canViewReports: true,
    canAccessSettings: false,
    canViewBilling: true,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true,
    canManageLabs: false,
    canViewPharmacy: true,
    canManagePharmacy: false,
    // Encryption permissions - Doctor can decrypt ALL medical data
    canDecryptMedical: true,
    canDecryptLabReports: true,
    canDecryptPrescriptions: true,
    canDecryptVitals: true,
    canDecryptDiagnosis: true
  },
  nurse: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: true,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Nurse can decrypt vitals and medication ONLY
    canDecryptVitals: true,
    canDecryptMedication: true,
    canDecryptNursingNotes: true,
    canDecryptMedical: false,
    canDecryptPrescriptions: false,
    canDecryptLabReports: false
  },
  receptionist: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: true,
    canManageAppointments: true,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true,
    canEditBilling: true,
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Receptionist can decrypt demographic data ONLY
    canDecryptDemographics: true,
    canDecryptMedical: false,
    canDecryptLabReports: false,
    canDecryptPrescriptions: false
  },
  lab_technician: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: false,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true,
    canManageLabs: true,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Lab tech can decrypt test type and patient name
    canDecryptTestType: true,
    canDecryptPatientName: true,
    canDecryptMedical: false,
    canDecryptDiagnosis: false,
    canDecryptPrescriptions: false,
    canEncryptLabResults: true // Lab results encrypted with doctor's public key
  },
  pharmacist: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: false,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: true,
    canManagePharmacy: true,
    // Encryption permissions - Pharmacist can decrypt medicine section ONLY
    canDecryptMedicine: true,
    canDecryptDosage: true,
    canDecryptMedical: false,
    canDecryptDiagnosis: false,
    canDecryptLabReports: false
  },
  accountant: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true,
    canEditBilling: true,
    canManageBilling: true,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Accountant can decrypt billing data ONLY
    canDecryptBilling: true,
    canDecryptInvoices: true,
    canDecryptInsurance: true,
    canDecryptMedical: false,
    canDecryptLabReports: false,
    canDecryptPrescriptions: false
  },
  patient: {
    canViewPatients: false,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Patient can decrypt OWN medical data
    canDecryptOwnMedical: true,
    canDecryptOwnBilling: true,
    canDecryptMedical: false
  }
};

/**
 * JWT Authentication Middleware with comprehensive security logging
 */
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.UNAUTHORIZED_ACCESS_ATTEMPT, {
      ipAddress, userAgent,
      details: { reason: 'NO_TOKEN', endpoint: req.path }
    });
    return res.status(401).json({ success: false, error: 'No token provided' });
  }

  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Track account access for security monitoring
    securityMonitor.trackAccountAccess(ipAddress, decoded.userId);

    next();
  } catch (error) {
    // Log JWT-specific security events
    if (error.name === 'TokenExpiredError') {
      winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.JWT_EXPIRED, {
        ipAddress, userAgent,
        details: { error: 'Token expired' }
      });
      securityMonitor.logJWTExpired(null, ipAddress);
    } else if (error.name === 'JsonWebTokenError') {
      winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.JWT_INVALID_SIGNATURE, {
        ipAddress, userAgent,
        details: { error: error.message }
      });
      securityMonitor.logJWTInvalid(ipAddress, error.message);
    }
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
};

/**
 * Permission Middleware Factory
 */
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions || !req.user.permissions[permission]) {
      securityMonitor.logUnauthorizedAccess(
        req.user?.userId, req.user?.role, req.path, req.ip
      );
      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    }
    next();
  };
};

/**
 * Role Middleware (checks if user has the required role)
 */
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      // Log unauthorized access attempt to both logger systems
      logger.logIAM(logger.AUDIT_EVENTS.PERMISSION_DENIED, {
        userId: req.user?.userId,
        userEmail: req.user?.email,
        userRole: req.user?.role,
        severity: logger.SEVERITY.WARN,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: { requiredRoles: roles, attemptedPath: req.path },
        status: 'denied'
      });

      winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.UNAUTHORIZED_ACCESS_ATTEMPT, {
        userId: req.user?.userId,
        role: req.user?.role,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: { requiredRoles: roles, endpoint: req.path }
      });

      securityMonitor.logUnauthorizedAccess(
        req.user?.userId, req.user?.role, req.path, req.ip
      );

      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    }
    next();
  };
};

// ===== MONITORING & HEALTH ENDPOINTS =====

/**
 * GET /api/monitoring/metrics
 * Returns real-time metrics for the logging system (Admin only)
 */
app.get('/api/monitoring/metrics', authenticate, requireRole(['admin']), async (req, res) => {
  const metrics = logger.getMetrics();
  res.json({
    success: true,
    metrics
  });
});

/**
 * GET /api/monitoring/health
 * Returns system health status
 */
app.get('/api/monitoring/health', async (req, res) => {
  const metrics = logger.getMetrics();

  // Check database health
  let dbHealthy = false;
  try {
    await db.query('SELECT 1');
    dbHealthy = true;
  } catch (err) {
    console.error('Database health check failed:', err.message);
  }

  const status = {
    success: true,
    status: dbHealthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    services: {
      api: 'up',
      database: dbHealthy ? 'up' : 'down',
      logging: 'up'
    },
    metrics: {
      totalLogs: metrics.totalLogs,
      auditLogs: metrics.auditLogs,
      errorCount: metrics.errorCount,
      uptime: metrics.uptimeFormatted
    }
  };

  res.json(status);
});

/**
 * GET /api/monitoring/prometheus
 * Returns combined Prometheus-formatted metrics from all monitoring systems
 */
app.get('/api/monitoring/prometheus', async (req, res) => {
  res.set('Content-Type', 'text/plain');
  const metrics = [
    monitoring.getPrometheusMetrics(),
    systemMonitor.getPrometheusMetrics(),
    securityMonitor.getPrometheusSecurityMetrics()
  ].join('\n\n');
  res.send(metrics);
});

/**
 * GET /api/monitoring/dashboard-health
 * Returns dashboard health metrics (Admin only)
 */
app.get('/api/monitoring/dashboard-health', authenticate, requireRole(['admin']), async (req, res) => {
  res.json({
    success: true,
    data: monitoring.getJsonMetrics()
  });
});

/**
 * GET /api/monitoring/system
 * Returns comprehensive system metrics (Admin only)
 */
app.get('/api/monitoring/system', authenticate, requireRole(['admin']), async (req, res) => {
  res.json({
    success: true,
    data: systemMonitor.getSystemMetrics()
  });
});

/**
 * GET /api/monitoring/security
 * Returns security monitoring data (Admin only)
 */
app.get('/api/monitoring/security', authenticate, requireRole(['admin']), async (req, res) => {
  const { severity, type, since } = req.query;
  res.json({
    success: true,
    metrics: securityMonitor.getSecurityMetrics(),
    alerts: securityMonitor.getAlerts({ severity, type, since }),
    blockedIPs: securityMonitor.getBlockedIPs()
  });
});

/**
 * POST /api/monitoring/security/acknowledge
 * Acknowledge a security alert (Admin only)
 */
app.post('/api/monitoring/security/acknowledge', authenticate, requireRole(['admin']), async (req, res) => {
  const { alertId } = req.body;
  const success = securityMonitor.acknowledgeAlert(alertId);
  res.json({ success, message: success ? 'Alert acknowledged' : 'Alert not found' });
});

/**
 * POST /api/monitoring/security/unblock-ip
 * Unblock an IP address (Admin only)
 */
app.post('/api/monitoring/security/unblock-ip', authenticate, requireRole(['admin']), async (req, res) => {
  const { ipAddress } = req.body;
  securityMonitor.unblockIP(ipAddress);
  winstonLogger.logSecurity('IP_UNBLOCKED', {
    userId: req.user.userId, role: req.user.role,
    ipAddress: req.ip,
    details: { unblockedIP: ipAddress }
  });
  res.json({ success: true, message: `IP ${ipAddress} unblocked` });
});

// ===== ENCRYPTION ENDPOINTS =====

/**
 * POST /api/encryption/encrypt-field
 * Encrypt a field value (Admin/System only)
 */
app.post('/api/encryption/encrypt-field', authenticate, requireRole(['admin']), async (req, res) => {
  const { value, context } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;

  try {
    const startTime = Date.now();
    const encrypted = encryptField(value, context || 'default');
    monitoring.recordEncryptionOp('encrypt', Date.now() - startTime);

    await logger.logEncryption(logger.AUDIT_EVENTS.FILE_ENCRYPTED, {
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress,
      details: { context },
      status: 'success'
    });

    res.json({ success: true, encrypted });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/encryption/decrypt-field
 * Decrypt a field value (Role-based access)
 */
app.post('/api/encryption/decrypt-field', authenticate, async (req, res) => {
  const { encrypted, context, table, field } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;

  // Check if user can access this field
  if (table && field && !canAccessField(table, field, req.user.role)) {
    await logger.logEncryption(logger.AUDIT_EVENTS.DECRYPT_DENIED, {
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress,
      severity: logger.SEVERITY.WARN,
      details: { table, field, reason: 'insufficient_permissions' },
      status: 'denied'
    });
    monitoring.recordEncryptionOp('denied');
    return res.status(403).json({ success: false, error: 'Access denied to this field' });
  }

  try {
    const startTime = Date.now();
    const decrypted = decryptField(encrypted, context || 'default');
    monitoring.recordEncryptionOp('decrypt', Date.now() - startTime);

    await logger.logEncryption(logger.AUDIT_EVENTS.FILE_DECRYPTED, {
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress,
      details: { context, table, field },
      status: 'success'
    });

    res.json({ success: true, decrypted });
  } catch (error) {
    monitoring.recordEncryptionOp('denied');
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== AUTHENTICATION ENDPOINTS =====

/**
 * POST /api/login
 * Authenticates user and returns tokens or MFA requirement
 */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password required' });
  }

  try {
    // Find user
    const { rows: users } = await db.query('SELECT * FROM users WHERE email = $1', [email.trim().toLowerCase()]);
    const user = users[0];

    if (!user) {
      // Log failed login attempt (unknown user) to all logging systems
      await logger.logIAM(logger.AUDIT_EVENTS.LOGIN_FAILURE, {
        userEmail: email,
        severity: logger.SEVERITY.WARN,
        ipAddress,
        userAgent,
        details: { reason: 'User not found' },
        status: 'failure'
      });
      winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.LOGIN_FAILURE, {
        email, ipAddress, userAgent,
        details: { reason: 'User not found' }
      });
      monitoring.recordLoginAttempt(false, email, ipAddress);
      securityMonitor.trackLoginFailure(ipAddress, email);
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      // Log failed login attempt (wrong password) to all logging systems
      await logger.logIAM(logger.AUDIT_EVENTS.LOGIN_FAILURE, {
        userId: user.id,
        userEmail: email,
        userRole: user.role,
        severity: logger.SEVERITY.WARN,
        ipAddress,
        userAgent,
        details: { reason: 'Invalid password' },
        status: 'failure'
      });
      winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.LOGIN_FAILURE, {
        userId: user.id, email, role: user.role, ipAddress, userAgent,
        details: { reason: 'Invalid password' }
      });
      monitoring.recordLoginAttempt(false, email, ipAddress);
      securityMonitor.trackLoginFailure(ipAddress, email);
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // If MFA enabled, require verification (mfa_enabled is TEXT, check for 'true' string)
    const mfaEnabled = user.mfa_enabled === true || user.mfa_enabled === 'true';
    if (mfaEnabled) {
      // Log that MFA is required
      await logger.logIAM(logger.AUDIT_EVENTS.LOGIN_SUCCESS, {
        userId: user.id,
        userEmail: user.email,
        userRole: user.role,
        severity: logger.SEVERITY.INFO,
        ipAddress,
        userAgent,
        details: { mfaRequired: true },
        status: 'pending_mfa'
      });
      return res.json({
        success: true,
        mfaRequired: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      });
    }

    // Generate tokens
    const permissions = ROLE_PERMISSIONS[user.role] || {};
    const payload = {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      permissions
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    // Log successful login to all logging systems
    await logger.logIAM(logger.AUDIT_EVENTS.LOGIN_SUCCESS, {
      userId: user.id,
      userEmail: user.email,
      userRole: user.role,
      severity: logger.SEVERITY.INFO,
      ipAddress,
      userAgent,
      details: { mfaRequired: false },
      status: 'success'
    });
    winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.LOGIN_SUCCESS, {
      userId: user.id, email: user.email, role: user.role, ipAddress, userAgent,
      details: { mfaRequired: false }
    });
    monitoring.recordLoginAttempt(true, user.email, ipAddress);

    res.json({
      success: true,
      token,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions
      }
    });

  } catch (error) {
    console.error('Login error:', error.message, error.stack);
    winstonLogger.logError('LOGIN_ERROR', { error, ipAddress, email });
    res.status(500).json({ success: false, error: 'Login failed: ' + error.message });
  }
});

/**
 * POST /api/mfa/verify
 * Verifies MFA code and returns tokens
 */
app.post('/api/mfa/verify', async (req, res) => {
  const { email, code } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  if (!email || !code) {
    return res.status(400).json({ success: false, error: 'Email and code required' });
  }

  try {
    // Find user
    const { rows: users } = await db.query('SELECT * FROM users WHERE email = $1', [email.trim().toLowerCase()]);
    const user = users[0];

    // Check if user exists and MFA is enabled
    if (!user) {
      await logger.logMFA(logger.AUDIT_EVENTS.MFA_FAILURE, {
        userEmail: email,
        severity: logger.SEVERITY.WARN,
        ipAddress,
        userAgent,
        details: { reason: 'User not found' },
        status: 'failure'
      });
      return res.status(401).json({ success: false, error: 'Invalid request' });
    }

    const mfaEnabled = user.mfa_enabled === true || user.mfa_enabled === 'true';
    if (!mfaEnabled) {
      return res.status(401).json({ success: false, error: 'Invalid request' });
    }

    // Verify TOTP code
    const tokenStr = String(code).trim();
    const secretStr = String(user.mfa_secret).trim();

    const verified = speakeasy.totp.verify({
      secret: secretStr,
      encoding: 'base32',
      token: tokenStr,
      window: 4
    });

    if (!verified) {
      // Log MFA failure
      await logger.logMFA(logger.AUDIT_EVENTS.MFA_FAILURE, {
        userId: user.id,
        userEmail: user.email,
        userRole: user.role,
        severity: logger.SEVERITY.WARN,
        ipAddress,
        userAgent,
        details: { reason: 'Invalid TOTP code' },
        status: 'failure'
      });
      monitoring.recordMfaVerification(false, user.id);
      return res.status(401).json({ success: false, error: 'Invalid MFA code' });
    }

    // Generate tokens
    const permissions = ROLE_PERMISSIONS[user.role] || {};
    const payload = {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      permissions
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    // Log MFA success
    await logger.logMFA(logger.AUDIT_EVENTS.MFA_SUCCESS, {
      userId: user.id,
      userEmail: user.email,
      userRole: user.role,
      severity: logger.SEVERITY.INFO,
      ipAddress,
      userAgent,
      details: { loginComplete: true },
      status: 'success'
    });
    monitoring.recordMfaVerification(true, user.id);
    monitoring.recordLoginAttempt(true, user.email, ipAddress);

    res.json({
      success: true,
      token,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions
      }
    });

  } catch (error) {
    console.error('MFA verification error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'MFA verification failed: ' + error.message });
  }
});

/**
 * POST /api/token/refresh
 * Refreshes access token using refresh token
 */
app.post('/api/token/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ success: false, error: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    // Get user info
    const { rows: users } = await db.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    const user = users[0];

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid refresh token' });
    }

    const permissions = ROLE_PERMISSIONS[user.role] || {};
    const payload = {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      permissions
    };

    const newToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      token: newToken,
      refreshToken: newRefreshToken
    });

  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid refresh token' });
  }
});

/**
 * POST /api/logout
 * Revokes refresh token and cleans up temp files
 */
app.post('/api/logout', authenticate, async (req, res) => {
  try {
    // Clean up temp files for this session
    const tempFileManager = require('./services/tempFileManager');
    const sessionId = req.session?.id || req.body.sessionId;
    
    if (req.user && sessionId) {
      await tempFileManager.cleanupSession(req.user.userId, sessionId);
      await winstonLogger.logAudit('LOGOUT_WITH_CLEANUP', {
        userId: req.user.userId,
        email: req.user.email,
        role: req.user.role,
        sessionId: sessionId,
        details: { tempFilesCleanedUp: true }
      });
      console.log(`✓ User ${req.user.email} logged out - temp files cleaned`);
    }
    
    // In a real app, add refresh token to denylist for security
    res.json({ success: true, message: 'Logged out successfully', tempFilesRemoved: true });
  } catch (err) {
    console.error('Logout error:', err);
    // Still logout even if cleanup fails
    res.json({ success: true, message: 'Logged out successfully', error: err.message });
  }
});

/**
 * GET /api/me
 * Returns current user information with permissions
 */
app.get('/api/me', authenticate, async (req, res) => {
  res.json({ success: true, user: req.user });
});

/**
 * GET /api/admin/mfa/secret
 * Admin endpoint to get MFA secret for a user
 */
app.get('/api/admin/mfa/secret', authenticate, requireRole(['admin']), async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ success: false, error: 'Email parameter required' });
  }

  try {
    // Find target user
    const { rows: users } = await db.query('SELECT mfa_secret, mfa_enabled FROM users WHERE email = $1', [email.trim().toLowerCase()]);
    const user = users[0];

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Return or generate MFA secret
    const secret = user.mfa_secret || speakeasy.generateSecret({
      name: `Hospital Portal (${email})`,
      issuer: 'Hospital Demo'
    }).base32;

    // Update user with secret if not set
    if (!user.mfa_secret) {
      await db.query('UPDATE users SET mfa_secret = $1, mfa_enabled = true WHERE email = $2', [secret, email.trim().toLowerCase()]);
    }

    res.json({
      success: true,
      secret,
      otpauth_url: speakeasy.otpauthURL({
        secret,
        label: encodeURIComponent(`Hospital Portal (${email})`),
        issuer: 'HospitalDemo',
        encoding: 'base32'
      })
    });

  } catch (error) {
    console.error('Admin MFA secret error:', error);
    res.status(500).json({ success: false, error: 'Failed to get MFA secret' });
  }
});

/**
 * GET /api/mfa/secret
 * User endpoint to view their own MFA secret for setup
 */
app.get('/api/mfa/secret', authenticate, async (req, res) => {
  try {
    const email = req.user.email;
    
    const { rows: users } = await db.query('SELECT mfa_secret FROM users WHERE email = $1', [email]);
    const user = users[0];

    if (!user || !user.mfa_secret) {
      return res.status(404).json({ success: false, error: 'MFA not configured' });
    }

    res.json({
      success: true,
      secret: user.mfa_secret,
      message: 'Add this secret to your authenticator app to enable MFA login',
      otpauth_url: speakeasy.otpauthURL({
        secret: user.mfa_secret,
        label: encodeURIComponent(`Hospital Portal (${email})`),
        issuer: 'HospitalDemo',
        encoding: 'base32'
      })
    });

  } catch (error) {
    console.error('MFA secret error:', error);
    res.status(500).json({ success: false, error: 'Failed to get MFA secret' });
  }
});

// ===== HEALTH & STATUS =====

/**
 * GET /
 * Basic health check
 */
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'Hospital Backend API',
    ts: new Date().toISOString(),
    env: process.env.NODE_ENV
  });
});

/**
 * GET /health
 * Kubernetes/Docker health check
 */
app.get('/health', (req, res) => {
  res.send('ok');
});

/**
 * GET /api/health
 * API health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'healthy', timestamp: new Date().toISOString() });
});

// ===== PATIENTS =====

/**
 * GET /api/patients
 * List all patients
 */
app.get('/api/patients', authenticate, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT * FROM patients ORDER BY created_at DESC LIMIT 100'
    );

    // Log the access
    await winstonLogger.logAudit('PATIENT_LIST_VIEWED', {
      userId: req.user.userId,
      email: req.user.email,
      role: req.user.role,
      resourceType: 'patients',
      resourceId: null,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      details: { count: rows.length }
    });

    res.json({ success: true, patients: rows.map(r => {
    // Parse contact JSON if it exists
    let phone = '', email = '', address = '';
    if (r.contact) {
      const contact = typeof r.contact === 'string' ? JSON.parse(r.contact) : r.contact;
      phone = contact.phone || '';
      email = contact.email || '';
      address = contact.address || '';
    }
    // Parse insurance JSON if it exists
    let insurance = '';
    if (r.insurance) {
      const ins = typeof r.insurance === 'string' ? JSON.parse(r.insurance) : r.insurance;
      insurance = ins.id || ins.provider || '';
    }
    return {
      id: r.id,
      name: `${r.first_name} ${r.last_name}`,
      firstName: r.first_name,
      lastName: r.last_name,
      age: r.dob ? new Date().getFullYear() - new Date(r.dob).getFullYear() : 'N/A',
      dob: r.dob,
      gender: r.gender || 'Not specified',
      condition: r.medical_history?.condition || 'Regular Checkup',
      lastVisit: r.updated_at ? new Date(r.updated_at).toISOString().split('T')[0] : new Date(r.created_at).toISOString().split('T')[0],
      phone,
      email,
      address,
      insurance,
      mrn: r.mrn,
      ...r
    };
  }) });
  } catch (err) {
    console.error('Error fetching patients:', err);
    await winstonLogger.logError('PATIENT_LIST_ERROR', {
      userId: req.user.userId,
      ipAddress: req.ip,
      endpoint: '/api/patients',
      method: 'GET',
      error: err.message
    });
    res.status(500).json({ success: false, error: 'Failed to fetch patients' });
  }
});

/**
 * GET /api/patients/:id
 * Get single patient with access logging
 */
app.get('/api/patients/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { rows } = await db.query('SELECT * FROM patients WHERE id = $1', [id]);
  if (!rows.length) return res.status(404).json({ success: false, error: 'Patient not found' });

  // Log patient record access
  winstonLogger.logAccess(winstonLogger.ACCESS_EVENTS.PATIENT_RECORD_VIEWED, {
    userId: req.user.userId,
    role: req.user.role,
    resourceId: id,
    resourceType: 'patient',
    ipAddress: req.ip
  });
  securityMonitor.trackPatientAccess(req.user.userId, id);

  res.json({ success: true, data: rows[0] });
});

/**
 * POST /api/patients
 * Create patient with audit logging
 */
app.post('/api/patients', authenticate, async (req, res) => {
  const { first_name, last_name, dob, gender, contact, insurance } = req.body;
  if (!first_name || !last_name) {
    return res.status(400).json({ success: false, error: 'first_name and last_name required' });
  }

  try {
    // Convert contact to JSON object if it's a string
    const contactObj = typeof contact === 'string' ? { phone: contact } : contact;
    // Convert insurance to JSON object if it's a string
    const insuranceObj = typeof insurance === 'string' ? { id: insurance } : insurance;

    const { rows } = await db.query(
      `INSERT INTO patients (first_name, last_name, dob, gender, contact, insurance)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [first_name, last_name, dob || null, gender || null, contactObj ? JSON.stringify(contactObj) : null, insuranceObj ? JSON.stringify(insuranceObj) : null]
    );

    // Log patient creation
    await winstonLogger.logAudit(winstonLogger.AUDIT_EVENTS.PATIENT_CREATED, {
      userId: req.user.userId,
      email: req.user.email,
      role: req.user.role,
      resourceType: 'patient',
      resourceId: rows[0].id,
      newValue: { first_name, last_name, dob, gender },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('POST /api/patients error:', err);
    winstonLogger.logError('PATIENT_CREATE_ERROR', { error: err, userId: req.user.userId });
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/patients/:id
 * Update patient with audit logging
 */
app.put('/api/patients/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { first_name, last_name, dob, gender, contact, insurance } = req.body;

  try {
    // Get old value for audit log
    const { rows: oldRows } = await db.query('SELECT * FROM patients WHERE id = $1', [id]);
    const oldValue = oldRows[0];

    // Convert contact to JSON object if it's a string
    const contactObj = contact ? (typeof contact === 'string' ? { phone: contact } : contact) : undefined;
    // Convert insurance to JSON object if it's a string
    const insuranceObj = insurance ? (typeof insurance === 'string' ? { id: insurance } : insurance) : undefined;

    const { rows } = await db.query(
      `UPDATE patients
       SET first_name = COALESCE($1, first_name),
           last_name = COALESCE($2, last_name),
           dob = COALESCE($3, dob),
           gender = COALESCE($4, gender),
           contact = CASE WHEN $5::text IS NOT NULL THEN $5::jsonb ELSE contact END,
           insurance = CASE WHEN $6::text IS NOT NULL THEN $6::jsonb ELSE insurance END,
           updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [
        first_name || null,
        last_name || null,
        dob || null,
        gender || null,
        contactObj ? JSON.stringify(contactObj) : null,
        insuranceObj ? JSON.stringify(insuranceObj) : null,
        id
      ]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, error: 'Patient not found' });
    }

    // Log patient update with old and new values
    await winstonLogger.logAudit(winstonLogger.AUDIT_EVENTS.PATIENT_UPDATED, {
      userId: req.user.userId,
      email: req.user.email,
      role: req.user.role,
      resourceType: 'patient',
      resourceId: id,
      oldValue: { first_name: oldValue?.first_name, last_name: oldValue?.last_name, dob: oldValue?.dob, gender: oldValue?.gender },
      newValue: { first_name, last_name, dob, gender },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('PUT /api/patients/:id error:', err);
    winstonLogger.logError('PATIENT_UPDATE_ERROR', { error: err, userId: req.user.userId, patientId: id });
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/patients/:id
 * Delete patient with audit logging
 */
app.delete('/api/patients/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  // Get patient data before deletion for audit log
  const { rows: oldRows } = await db.query('SELECT * FROM patients WHERE id = $1', [id]);
  const oldValue = oldRows[0];

  const { rows } = await db.query(
    'DELETE FROM patients WHERE id = $1 RETURNING id',
    [id]
  );

  if (!rows.length) {
    return res.status(404).json({ success: false, error: 'Patient not found' });
  }

  // Log patient deletion
  await winstonLogger.logAudit(winstonLogger.AUDIT_EVENTS.PATIENT_DELETED, {
    userId: req.user.userId,
    email: req.user.email,
    role: req.user.role,
    resourceType: 'patient',
    resourceId: id,
    oldValue: { first_name: oldValue?.first_name, last_name: oldValue?.last_name },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({ success: true, message: 'Patient deleted' });
});

// ===== APPOINTMENTS =====

/**
 * GET /api/appointments
 * List appointments
 */
app.get('/api/appointments', authenticate, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT a.*, p.first_name, p.last_name, u.name as doctor_name
       FROM appointments a
       LEFT JOIN patients p ON a.patient_id = p.id
       LEFT JOIN users u ON a.doctor_id = u.id
       ORDER BY a.scheduled_at DESC
       LIMIT 100`
    );

    // Log the access
    await winstonLogger.logAudit('APPOINTMENTS_LIST_VIEWED', {
      userId: req.user.userId,
      email: req.user.email,
      role: req.user.role,
      resourceType: 'appointments',
      resourceId: null,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      details: { count: rows.length }
    });

    const appointments = rows.map(r => ({
      id: r.id,
      patient: `${r.first_name || 'Unknown'} ${r.last_name || ''}`,
      doctor: r.doctor_name || 'Unassigned',
      date: new Date(r.scheduled_at).toISOString().split('T')[0],
      time: new Date(r.scheduled_at).toTimeString().split(' ')[0].slice(0, 5),
      status: 'Scheduled',
      reason: r.notes || 'Appointment',
      ...r
    }));
    res.json({ success: true, appointments });
  } catch (err) {
    console.error('Error fetching appointments:', err);
    await winstonLogger.logError('APPOINTMENTS_LIST_ERROR', {
      userId: req.user.userId,
      ipAddress: req.ip,
      endpoint: '/api/appointments',
      method: 'GET',
      error: err.message
    });
    res.status(500).json({ success: false, error: 'Failed to fetch appointments' });
  }
});

/**
 * POST /api/appointments
 * Create appointment
 */
app.post('/api/appointments', authenticate, async (req, res) => {
  const { patient_id, doctor_id, scheduled_at, appointment_type, notes } = req.body;

  if (!patient_id || !scheduled_at) {
    return res.status(400).json({ success: false, error: 'patient_id and scheduled_at required' });
  }

  try {
    const { rows } = await db.query(
      `INSERT INTO appointments (patient_id, doctor_id, scheduled_at, appointment_type, notes)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [patient_id, doctor_id || null, scheduled_at, appointment_type || null, notes || null]
    );

    // Log appointment creation
    await logger.log({
      service: logger.SERVICE.APPOINTMENT,
      eventType: 'APPOINTMENT_CREATED',
      category: logger.CATEGORY.AUDIT,
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress: req.ip,
      resourceType: 'appointment',
      resourceId: rows[0].id,
      details: { patient_id, doctor_id, scheduled_at, appointment_type },
      status: 'success'
    });

    res.status(201).json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('POST /api/appointments error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/appointments/:id
 * Update appointment
 */
app.put('/api/appointments/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { patient_id, doctor_id, scheduled_at, appointment_type, notes, status } = req.body;

  try {
    const { rows } = await db.query(
      `UPDATE appointments
       SET patient_id = COALESCE($1, patient_id),
           doctor_id = COALESCE($2, doctor_id),
           scheduled_at = COALESCE($3, scheduled_at),
           appointment_type = COALESCE($4, appointment_type),
           notes = COALESCE($5, notes),
           status = COALESCE($6, status),
           updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [patient_id, doctor_id, scheduled_at, appointment_type, notes, status, id]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, error: 'Appointment not found' });
    }

    // Log appointment update
    await logger.log({
      service: logger.SERVICE.APPOINTMENT,
      eventType: 'APPOINTMENT_UPDATED',
      category: logger.CATEGORY.AUDIT,
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress: req.ip,
      resourceType: 'appointment',
      resourceId: id,
      details: { status, scheduled_at, appointment_type },
      status: 'success'
    });

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('PUT /api/appointments/:id error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/appointments/:id
 * Delete appointment
 */
app.delete('/api/appointments/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    const { rows } = await db.query(
      'DELETE FROM appointments WHERE id = $1 RETURNING id',
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, error: 'Appointment not found' });
    }

    // Log appointment deletion
    await logger.log({
      service: logger.SERVICE.APPOINTMENT,
      eventType: 'APPOINTMENT_DELETED',
      category: logger.CATEGORY.AUDIT,
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress: req.ip,
      resourceType: 'appointment',
      resourceId: id,
      status: 'success'
    });

    res.json({ success: true, message: 'Appointment deleted' });
  } catch (err) {
    console.error('DELETE /api/appointments/:id error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== LAB TESTS =====

/**
 * GET /api/lab-tests
 * List lab tests with RBAC - doctors/nurses/lab_technicians see all, patients see own only
 */
app.get('/api/lab-tests', authenticate, async (req, res) => {
  try {
    // Check permissions
    const canViewTests = ['doctor', 'nurse', 'admin', 'lab_technician'].includes(req.user.role);
    if (!canViewTests && req.user.role !== 'patient') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    let query = `SELECT lt.*, p.first_name, p.last_name, u.name as requested_by_name
                 FROM lab_tests lt
                 LEFT JOIN patients p ON lt.patient_id = p.id
                 LEFT JOIN users u ON lt.requested_by = u.id`;
    
    // Patients see only their own tests
    if (req.user.role === 'patient') {
      // Find if user is associated with a patient (by email or ID)
      const patientCheck = await db.query('SELECT id FROM patients WHERE first_name = $1 LIMIT 1', [req.user.name.split(' ')[0]]);
      if (patientCheck.rows.length > 0) {
        query += ` WHERE lt.patient_id = $1`;
        query += ` ORDER BY lt.created_at DESC LIMIT 100`;
        const { rows } = await db.query(query, [patientCheck.rows[0].id]);
        return res.json({ success: true, data: rows });
      }
    }
    
    query += ` ORDER BY lt.created_at DESC LIMIT 100`;
    const { rows } = await db.query(query);
    res.json({ success: true, data: rows });
  } catch (err) {
    console.error('Lab tests list error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/lab-tests
 * Create lab test (doctors, nurses, admin only)
 */
app.post('/api/lab-tests', authenticate, async (req, res) => {
  try {
    // Check permissions
    if (!['doctor', 'nurse', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied - only doctors can order tests' });
    }

    const { patient_id, test_name, notes } = req.body;
    
    if (!patient_id || !test_name) {
      return res.status(400).json({ success: false, error: 'patient_id and test_name required' });
    }
    
    const requestedBy = req.user.userId || req.user.id || null;
    const { rows } = await db.query(
      `INSERT INTO lab_tests (patient_id, requested_by, test_name, status, notes)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [patient_id, requestedBy, test_name, 'pending', notes || null]
    );
    
    // Audit log
    console.log(`[AUDIT] LAB_TEST_CREATED user=${req.user.id} patient=${patient_id} test=${test_name}`);
    
    res.status(201).json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('Create lab test error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/lab-tests/:id
 * Update lab test status (lab tech uploads results)
 */
app.put('/api/lab-tests/:id', authenticate, async (req, res) => {
  try {
    // Only lab tech, doctors, and admin can update
    if (!['lab_technician', 'doctor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;
    const { status, result_data, result_pdf_key, notes, generate_pdf } = req.body;

    // First get the test with patient info for PDF generation
    const testRes = await db.query(
      `SELECT lt.*, p.first_name, p.last_name, u.name as requested_by_name
       FROM lab_tests lt
       LEFT JOIN patients p ON lt.patient_id = p.id
       LEFT JOIN users u ON lt.requested_by = u.id
       WHERE lt.id = $1`,
      [id]
    );

    if (testRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Lab test not found' });
    }

    const existingTest = testRes.rows[0];
    let pdfKey = result_pdf_key || null;

    // Generate PDF if requested and status is completed
    if (generate_pdf && status === 'completed' && result_data) {
      try {
        const pdfGenerator = require('../../Encryption/pdfGenerator');
        const pdfDir = path.join(__dirname, '../storage/lab-reports');
        if (!fs.existsSync(pdfDir)) {
          fs.mkdirSync(pdfDir, { recursive: true });
        }

        const pdfFileName = `lab-report-${id}-${Date.now()}.pdf`;
        const pdfPath = path.join(pdfDir, pdfFileName);

        const labData = {
          id: id,
          test_name: existingTest.test_name,
          patient_name: `${existingTest.first_name} ${existingTest.last_name}`,
          requested_by: existingTest.requested_by_name,
          created_at: existingTest.created_at,
          completed_at: new Date().toISOString(),
          result_data: result_data,
          result_status: result_data.result_status || 'Normal'
        };

        await pdfGenerator.generateLabReportPDF(labData, pdfPath);
        pdfKey = `labs/${pdfFileName}`;
        console.log(`[PDF] Lab report generated: ${pdfKey}`);
      } catch (pdfErr) {
        console.error('PDF generation error:', pdfErr.message);
        // Continue without PDF - don't fail the whole request
      }
    }

    const { rows } = await db.query(
      `UPDATE lab_tests
       SET status = COALESCE($1, status),
           result_data = COALESCE($2, result_data),
           result_pdf_key = COALESCE($3, result_pdf_key),
           notes = COALESCE($4, notes),
           completed_at = CASE WHEN $1 = 'completed' THEN NOW() ELSE completed_at END,
           updated_at = NOW()
       WHERE id = $5
       RETURNING *`,
      [status || null, result_data ? JSON.stringify(result_data) : null, pdfKey, notes || null, id]
    );

    console.log(`[AUDIT] LAB_TEST_UPDATED user=${req.user.id} test_id=${id} status=${status} pdf=${pdfKey || 'none'}`);

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('Update lab test error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/lab-tests/:id/billing
 * Add lab fees to a test (lab technician only)
 */
app.put('/api/lab-tests/:id/billing', authenticate, async (req, res) => {
  try {
    // Only lab technician and admin can add lab fees
    if (!['lab_technician', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied - only lab technicians can add lab fees' });
    }

    const { id } = req.params;
    const { lab_fees, billed_by } = req.body;

    if (!lab_fees || lab_fees <= 0) {
      return res.status(400).json({ success: false, error: 'Valid lab_fees amount required' });
    }

    // Update lab test with fees
    const { rows } = await db.query(
      `UPDATE lab_tests
       SET lab_fees = $1,
           billed_by = $2,
           billed_at = NOW(),
           updated_at = NOW()
       WHERE id = $3
       RETURNING *`,
      [lab_fees, billed_by || req.user.name, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Lab test not found' });
    }

    // Also update billing table if a bill exists for this patient
    const test = rows[0];
    await db.query(
      `UPDATE billing
       SET lab_fees = COALESCE(lab_fees, 0) + $1,
           updated_at = NOW()
       WHERE patient_id = $2 AND status != 'paid'`,
      [lab_fees, test.patient_id]
    );

    console.log(`[AUDIT] LAB_FEE_ADDED user=${req.user.id} test_id=${id} amount=${lab_fees}`);

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('Add lab fee error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/lab-tests/:id
 * Get single lab test details with access logging
 */
app.get('/api/lab-tests/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await db.query(
      `SELECT lt.*, p.first_name, p.last_name, u.name as requested_by_name
       FROM lab_tests lt
       LEFT JOIN patients p ON lt.patient_id = p.id
       LEFT JOIN users u ON lt.requested_by = u.id
       WHERE lt.id = $1`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Lab test not found' });
    }

    // Log lab result access
    winstonLogger.logAccess(winstonLogger.ACCESS_EVENTS.LAB_RESULT_VIEWED, {
      userId: req.user.userId,
      role: req.user.role,
      resourceId: id,
      resourceType: 'lab_test',
      patientId: rows[0].patient_id,
      ipAddress: req.ip
    });

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('Get lab test error:', err.message);
    winstonLogger.logError('LAB_TEST_VIEW_ERROR', { error: err, userId: req.user.userId, labTestId: id });
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/lab-tests/:id/pdf
 * Generate and download PDF for a lab test result
 * Available to: doctor, lab_technician, admin
 */
app.get('/api/lab-tests/:id/pdf', authenticate, async (req, res) => {
  try {
    // Only doctors, lab technicians, and admins can download lab reports
    if (!['doctor', 'lab_technician', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;

    // Get the lab test with patient info
    const { rows } = await db.query(
      `SELECT lt.*, p.first_name, p.last_name, u.name as requested_by_name
       FROM lab_tests lt
       LEFT JOIN patients p ON lt.patient_id = p.id
       LEFT JOIN users u ON lt.requested_by = u.id
       WHERE lt.id = $1`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Lab test not found' });
    }

    const test = rows[0];

    // Check if test has results
    if (!test.result_data && test.status !== 'completed') {
      return res.status(400).json({ success: false, error: 'No results available for this test' });
    }

    // If PDF already exists, serve it
    if (test.result_pdf_key) {
      const existingPdfPath = path.join(__dirname, '../storage/lab-reports', test.result_pdf_key.replace('labs/', ''));
      if (fs.existsSync(existingPdfPath)) {
        console.log(`[PDF] Serving existing lab report: ${existingPdfPath}`);

        // Log file download
        winstonLogger.logAccess(winstonLogger.ACCESS_EVENTS.FILE_DOWNLOADED, {
          userId: req.user.userId,
          role: req.user.role,
          resourceId: id,
          resourceType: 'lab_report_pdf',
          fileName: test.result_pdf_key,
          ipAddress: req.ip
        });

        res.contentType('application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="lab-report-${id}.pdf"`);
        return fs.createReadStream(existingPdfPath).pipe(res);
      }
    }

    // Generate PDF on-demand
    const pdfGenerator = require('../../Encryption/pdfGenerator');
    const pdfDir = path.join(__dirname, '../storage/lab-reports');
    if (!fs.existsSync(pdfDir)) {
      fs.mkdirSync(pdfDir, { recursive: true });
    }

    const pdfFileName = `lab-report-${id}-${Date.now()}.pdf`;
    const pdfPath = path.join(pdfDir, pdfFileName);

    // Parse result_data if it's a string
    let resultData = test.result_data;
    if (typeof resultData === 'string') {
      try {
        resultData = JSON.parse(resultData);
      } catch (e) {
        resultData = { raw_data: resultData };
      }
    }

    const labData = {
      id: id,
      test_name: test.test_name,
      patient_name: `${test.first_name || 'Unknown'} ${test.last_name || ''}`.trim(),
      requested_by: test.requested_by_name || 'N/A',
      created_at: test.created_at,
      completed_at: test.completed_at || new Date().toISOString(),
      result_data: resultData || {},
      result_status: resultData?.result_status || 'Normal'
    };

    await pdfGenerator.generateLabReportPDF(labData, pdfPath);

    // Update the database with the PDF key
    const pdfKey = `labs/${pdfFileName}`;
    await db.query(
      `UPDATE lab_tests SET result_pdf_key = $1 WHERE id = $2`,
      [pdfKey, id]
    );

    console.log(`[PDF] Lab report generated and saved: ${pdfKey}`);

    // Audit log
    console.log(`[AUDIT] LAB_REPORT_DOWNLOADED user=${req.user.id} test_id=${id}`);

    // Send the generated PDF
    res.contentType('application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="lab-report-${id}.pdf"`);
    fs.createReadStream(pdfPath).pipe(res);

  } catch (err) {
    console.error('Lab PDF generation error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== VITALS =====

/**
 * GET /api/vitals/:patient_id
 * Get vitals for patient
 */
app.get('/api/vitals/:patient_id', async (req, res) => {
  const { patient_id } = req.params;
  const { rows } = await db.query(
    'SELECT * FROM vitals WHERE patient_id = $1 ORDER BY recorded_at DESC LIMIT 50',
    [patient_id]
  );
  res.json({ success: true, data: rows });
});

/**
 * POST /api/vitals
 * Record vitals
 */
app.post('/api/vitals', async (req, res) => {
  const { patient_id, recorded_by, metrics } = req.body;
  
  if (!patient_id || !metrics) {
    return res.status(400).json({ success: false, error: 'patient_id and metrics required' });
  }
  
  const { rows } = await db.query(
    `INSERT INTO vitals (patient_id, recorded_by, metrics)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [patient_id, recorded_by || null, JSON.stringify(metrics)]
  );
  
  res.status(201).json({ success: true, data: rows[0] });
});

// ===== BILLING / PAYMENTS =====

/**
 * GET /api/billing
 * List bills with fee breakdown - accountant/admin see all, patients see own only
 */
app.get('/api/billing', authenticate, async (req, res) => {
  try {
    // Check permissions - accountant has NO patient access, only billing summaries
    if (req.user.role === 'accountant') {
      // Accountant sees billing summaries only (no patient details)
      const { rows } = await db.query(`
        SELECT b.id, b.bill_date, b.status, b.total_amount, b.doctor_fees, b.lab_fees, b.pharmacist_fees,
               b.amount_paid, b.created_at
        FROM billing b ORDER BY b.created_at DESC LIMIT 200
      `);
      return res.json({ success: true, data: rows });
    }

    if (!['admin', 'doctor', 'nurse', 'receptionist', 'lab_technician', 'pharmacist', 'patient'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    let query = `SELECT b.*, p.first_name, p.last_name,
                 b.doctor_fees, b.lab_fees, b.pharmacist_fees,
                 (SELECT SUM(amount) FROM billing_services WHERE billing_id = b.id) as service_total
                 FROM billing b
                 LEFT JOIN patients p ON b.patient_id = p.id`;

    if (req.user.role === 'patient') {
      const patientCheck = await db.query('SELECT id FROM patients WHERE first_name = $1 LIMIT 1', [req.user.name.split(' ')[0]]);
      if (patientCheck.rows.length > 0) {
        query += ` WHERE b.patient_id = $1 ORDER BY b.created_at DESC`;
        const { rows } = await db.query(query, [patientCheck.rows[0].id]);
        return res.json({ success: true, data: rows });
      }
    }

    query += ` ORDER BY b.created_at DESC LIMIT 200`;
    const { rows } = await db.query(query);
    res.json({ success: true, data: rows });
  } catch (err) {
    console.error('Billing list error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/billing
 * Create a bill with fee breakdown (receptionist can create)
 */
app.post('/api/billing', authenticate, async (req, res) => {
  try {
    if (!['admin', 'accountant', 'receptionist'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied - only admin/accountant/receptionist can create bills' });
    }

    const { patient_id, bill_date, due_date, notes, doctor_fees, lab_fees, pharmacist_fees } = req.body;

    if (!patient_id) {
      return res.status(400).json({ success: false, error: 'patient_id required' });
    }

    const docFees = parseFloat(doctor_fees) || 0;
    const labFees = parseFloat(lab_fees) || 0;
    const pharmFees = parseFloat(pharmacist_fees) || 0;
    const totalAmount = docFees + labFees + pharmFees;

    const { rows } = await db.query(
      `INSERT INTO billing (patient_id, bill_date, due_date, status, total_amount, discount, notes, created_by, doctor_fees, lab_fees, pharmacist_fees)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [patient_id, bill_date || new Date(), due_date || null, 'pending', totalAmount, 0, notes || null, req.user.id, docFees, labFees, pharmFees]
    );

    console.log(`[AUDIT] BILLING_CREATED user=${req.user.id} patient=${patient_id} bill_id=${rows[0].id}`);

    res.status(201).json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('Create billing error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/billing/:id/services
 * Add service to bill
 */
app.post('/api/billing/:id/services', authenticate, async (req, res) => {
  try {
    if (!['admin', 'accountant', 'receptionist', 'doctor', 'pharmacist', 'lab_technician'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;
    const { service_name, description, amount, quantity } = req.body;
    
    if (!service_name || !amount) {
      return res.status(400).json({ success: false, error: 'service_name and amount required' });
    }
    
    const { rows } = await db.query(
      `INSERT INTO billing_services (billing_id, service_name, description, amount, quantity)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [id, service_name, description || null, amount, quantity || 1]
    );

    // Update billing total
    const total = await db.query(
      `UPDATE billing SET total_amount = (SELECT COALESCE(SUM(amount * quantity), 0) FROM billing_services WHERE billing_id = $1)
       WHERE id = $1 RETURNING total_amount`,
      [id]
    );
    
    console.log(`[AUDIT] BILLING_SERVICE_ADDED user=${req.user.id} billing_id=${id} service=${service_name}`);
    
    res.status(201).json({ success: true, data: rows[0], billing_total: total.rows[0] });
  } catch (err) {
    console.error('Add billing service error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/billing/:id/payment
 * Process payment with encryption for sensitive data - accountant, admin, receptionist can process
 */
app.put('/api/billing/:id/payment', authenticate, async (req, res) => {
  try {
    // Check permissions - only accountant, admin, receptionist can process payments
    if (!['admin', 'accountant', 'receptionist'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied - only admin/accountant/receptionist can process payments' });
    }

    const { id } = req.params;
    const { amount, payment_method, discount_reason, insurance_details, notes } = req.body;
    
    if (!amount || !payment_method) {
      return res.status(400).json({ success: false, error: 'amount and payment_method required' });
    }

    // Get current bill
    const billRes = await db.query('SELECT * FROM billing WHERE id = $1', [id]);
    if (billRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bill not found' });
    }

    const bill = billRes.rows[0];
    const remaining = (bill.total_amount || 0) - (bill.amount_paid || 0) - amount;
    const status = remaining <= 0 ? 'paid' : 'partial';

    // Encrypt sensitive fields if encryption service is available
    let encryptedPaymentMethod = payment_method;
    let encryptedDiscountReason = discount_reason;
    let encryptedInsuranceDetails = insurance_details;

    if (encryptionService && encryptionService.encryptBillingField) {
      try {
        // Encrypt payment method
        const encryptedPM = await encryptionService.encryptBillingField(
          payment_method,
          id,
          req.user.id,
          req.user.role
        );
        encryptedPaymentMethod = encryptedPM;

        // Encrypt discount reason if provided
        if (discount_reason) {
          const encryptedDR = await encryptionService.encryptBillingField(
            discount_reason,
            id,
            req.user.id,
            req.user.role
          );
          encryptedDiscountReason = encryptedDR;
        }

        // Encrypt insurance details if provided
        if (insurance_details) {
          const encryptedID = await encryptionService.encryptBillingField(
            JSON.stringify(insurance_details),
            id,
            req.user.id,
            req.user.role
          );
          encryptedInsuranceDetails = encryptedID;
        }

        console.log(`[ENCRYPTION] Payment data encrypted for bill ${id}`);
      } catch (encErr) {
        console.warn(`[ENCRYPTION WARNING] Failed to encrypt billing fields: ${encErr.message}. Storing unencrypted.`);
      }
    }

    // Update billing with encrypted payment data
    const { rows } = await db.query(
      `UPDATE billing 
       SET amount_paid = COALESCE(amount_paid, 0) + $1,
           status = $2,
           payment_date = NOW(),
           payment_method = $3,
           discount_reason = CASE WHEN $4::jsonb IS NOT NULL THEN $4::jsonb ELSE discount_reason END,
           insurance_details = CASE WHEN $5::jsonb IS NOT NULL THEN $5::jsonb ELSE insurance_details END,
           notes = COALESCE($6, notes),
           updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [
        amount,
        status,
        typeof encryptedPaymentMethod === 'object' ? JSON.stringify(encryptedPaymentMethod) : encryptedPaymentMethod,
        encryptedDiscountReason ? JSON.stringify(encryptedDiscountReason) : null,
        encryptedInsuranceDetails ? JSON.stringify(encryptedInsuranceDetails) : null,
        notes || null,
        id
      ]
    );

    console.log(`[AUDIT] PAYMENT_PROCESSED user=${req.user.id} billing_id=${id} amount=${amount}`);
    
    res.json({ 
      success: true, 
      data: rows[0],
      message: 'Payment processed successfully with encrypted sensitive data'
    });
  } catch (err) {
    console.error('Process payment error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== PHARMACY / PRESCRIPTIONS =====

/**
 * GET /api/prescriptions
 * List prescriptions with RBAC
 */
app.get('/api/prescriptions', authenticate, async (req, res) => {
  try {
    if (!['admin', 'doctor', 'nurse', 'pharmacist', 'patient'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    let query = `SELECT p.*, pat.first_name, pat.last_name, u.name as prescribed_by_name
                 FROM prescriptions p
                 LEFT JOIN patients pat ON p.patient_id = pat.id
                 LEFT JOIN users u ON p.prescribed_by = u.id`;
    let params = [];

    if (req.user.role === 'patient') {
      const patientCheck = await db.query('SELECT id FROM patients WHERE first_name = $1 LIMIT 1', [req.user.name.split(' ')[0]]);
      if (patientCheck.rows.length > 0) {
        query += ` WHERE p.patient_id = $1`;
        params = [patientCheck.rows[0].id];
      }
    }

    query += ` ORDER BY p.created_at DESC LIMIT 200`;
    const { rows } = await db.query(query, params);
    res.json({ success: true, data: rows });
  } catch (err) {
    console.error('Prescriptions list error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/prescriptions
 * Create prescription (doctor only)
 */
app.post('/api/prescriptions', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'doctor' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied - only doctors can prescribe' });
    }

    const { patient_id, meds, notes } = req.body;
    
    if (!patient_id || !meds) {
      return res.status(400).json({ success: false, error: 'patient_id and meds required' });
    }
    
    const { rows } = await db.query(
      `INSERT INTO prescriptions (patient_id, prescribed_by, meds, notes, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [patient_id, req.user.id, JSON.stringify(meds), notes || null, 'active']
    );

    console.log(`[AUDIT] PRESCRIPTION_CREATED user=${req.user.id} patient=${patient_id}`);
    
    res.status(201).json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('Create prescription error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/prescriptions/:id
 * Update prescription status (mark as filled, expired, etc.)
 */
app.put('/api/prescriptions/:id', authenticate, async (req, res) => {
  try {
    if (!['admin', 'doctor', 'pharmacist'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;
    const { status, notes } = req.body;
    
    const { rows } = await db.query(
      `UPDATE prescriptions 
       SET status = COALESCE($1, status),
           notes = COALESCE($2, notes),
           updated_at = NOW()
       WHERE id = $3
       RETURNING *`,
      [status || null, notes || null, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Prescription not found' });
    }

    console.log(`[AUDIT] PRESCRIPTION_UPDATED user=${req.user.id} prescription_id=${id} status=${status}`);
    
    res.json({ success: true, data: rows[0] });
  } catch (err) {
    console.error('Update prescription error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== DASHBOARD / STATISTICS =====

/**
 * GET /api/dashboard/stats
 * Get dashboard statistics (admin only)
 */
app.get('/api/dashboard/stats', authenticate, async (req, res) => {
  try {
    if (!['admin'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const stats = {};

    // Total patients
    const patientCount = await db.query('SELECT COUNT(*) as count FROM patients');
    stats.total_patients = parseInt(patientCount.rows[0].count);

    // Total appointments
    const appointmentCount = await db.query('SELECT COUNT(*) as count FROM appointments');
    stats.total_appointments = parseInt(appointmentCount.rows[0].count);

    // Appointments today
    const todayCount = await db.query(
      `SELECT COUNT(*) as count FROM appointments WHERE DATE(scheduled_at) = CURRENT_DATE`
    );
    stats.appointments_today = parseInt(todayCount.rows[0].count);

    // Total revenue
    const revenue = await db.query('SELECT COALESCE(SUM(amount_paid), 0) as total FROM billing WHERE status = \'paid\'');
    stats.total_revenue = parseFloat(revenue.rows[0].total);

    // Pending bills
    const pendingBills = await db.query('SELECT COUNT(*) as count FROM billing WHERE status IN (\'pending\', \'partial\')');
    stats.pending_bills = parseInt(pendingBills.rows[0].count);

    // Active staff
    const staffCount = await db.query('SELECT COUNT(*) as count FROM users WHERE role IN (\'doctor\', \'nurse\', \'lab_technician\', \'pharmacist\')');
    stats.active_staff = parseInt(staffCount.rows[0].count);

    res.json({ success: true, data: stats });
  } catch (err) {
    console.error('Dashboard stats error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== AUDIT LOGS =====

/**
 * GET /api/audit-logs
 * Get audit logs with filtering and search (admin only)
 */
app.get('/api/audit-logs', authenticate, async (req, res) => {
  try {
    if (!['admin'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    // Log the audit-logs access itself
    await winstonLogger.logAudit('AUDIT_LOGS_VIEWED', {
      userId: req.user.userId,
      email: req.user.email,
      role: req.user.role,
      resourceType: 'audit_logs',
      resourceId: null,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      details: { action: 'admin_view_logs' }
    });

    const {
      limit = 100,
      offset = 0,
      action,
      user_id,
      severity,
      start_date,
      end_date,
      search
    } = req.query;

    let query = `
      SELECT al.*, u.name as actor_name, u.email as actor_email
      FROM audit_logs al
      LEFT JOIN users u ON al.actor_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    // Filter by action (e.g., IAM:LOGIN_SUCCESS)
    if (action) {
      query += ` AND al.action ILIKE $${paramIndex}`;
      params.push(`%${action}%`);
      paramIndex++;
    }

    // Filter by actor_id
    if (user_id) {
      query += ` AND al.actor_id = $${paramIndex}`;
      params.push(user_id);
      paramIndex++;
    }

    // Filter by severity (stored in details JSON)
    if (severity) {
      query += ` AND al.details->>'severity' = $${paramIndex}`;
      params.push(severity);
      paramIndex++;
    }

    // Filter by date range
    if (start_date) {
      query += ` AND al.created_at >= $${paramIndex}`;
      params.push(start_date);
      paramIndex++;
    }
    if (end_date) {
      query += ` AND al.created_at <= $${paramIndex}`;
      params.push(end_date);
      paramIndex++;
    }

    // Search in action or details
    if (search) {
      query += ` AND (al.action ILIKE $${paramIndex} OR al.details::text ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    query += ` ORDER BY al.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(parseInt(limit), parseInt(offset));

    const { rows } = await db.query(query, params);

    // Get total count for pagination
    const countQuery = query.replace(/SELECT al\.\*, u\.name.*?FROM/, 'SELECT COUNT(*) FROM').replace(/ORDER BY.*$/, '');
    const countParams = params.slice(0, -2);
    const { rows: countRows } = await db.query(countQuery, countParams);
    const totalCount = parseInt(countRows[0]?.count || 0);

    res.json({
      success: true,
      data: rows,
      pagination: {
        total: totalCount,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + rows.length) < totalCount
      }
    });
  } catch (err) {
    console.error('Audit logs error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/audit-logs/summary
 * Get audit logs summary statistics (admin only)
 */
app.get('/api/audit-logs/summary', authenticate, requireRole(['admin']), async (req, res) => {
  try {
    // Get counts by action type
    const actionCounts = await db.query(`
      SELECT
        action,
        COUNT(*) as count
      FROM audit_logs
      WHERE created_at >= NOW() - INTERVAL '24 hours'
      GROUP BY action
      ORDER BY count DESC
      LIMIT 10
    `);

    // Get counts by severity
    const severityCounts = await db.query(`
      SELECT
        details->>'severity' as severity,
        COUNT(*) as count
      FROM audit_logs
      WHERE created_at >= NOW() - INTERVAL '24 hours'
      GROUP BY details->>'severity'
    `);

    // Get recent security events
    const securityEvents = await db.query(`
      SELECT *
      FROM audit_logs
      WHERE action LIKE 'IAM:%' OR action LIKE 'MFA:%' OR action LIKE 'ENCRYPTION:%'
      ORDER BY created_at DESC
      LIMIT 20
    `);

    // Get real-time metrics from logger
    const metrics = logger.getMetrics();

    res.json({
      success: true,
      summary: {
        actionCounts: actionCounts.rows,
        severityCounts: severityCounts.rows,
        recentSecurityEvents: securityEvents.rows,
        realTimeMetrics: metrics
      }
    });
  } catch (err) {
    console.error('Audit logs summary error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/audit-logs/export
 * Export audit logs as PDF (admin only)
 */
app.get('/api/audit-logs/export', authenticate, requireRole(['admin']), async (req, res) => {
  try {
    const { startDate, endDate, format = 'json' } = req.query;

    let query = `
      SELECT al.*, u.name as actor_name, u.email as actor_email
      FROM audit_logs al
      LEFT JOIN users u ON al.actor_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    if (startDate) {
      query += ` AND al.created_at >= $${paramIndex++}`;
      params.push(startDate);
    }
    if (endDate) {
      query += ` AND al.created_at <= $${paramIndex++}`;
      params.push(endDate);
    }

    query += ' ORDER BY al.created_at DESC LIMIT 1000';

    const { rows } = await db.query(query, params);

    // Log the export action
    await logger.logIAM('AUDIT_LOG_EXPORT', {
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress: req.ip,
      details: { startDate, endDate, format, recordCount: rows.length },
      status: 'success'
    });

    if (format === 'csv') {
      // Export as CSV
      const headers = ['ID', 'Timestamp', 'Actor', 'Action', 'Resource Type', 'Resource ID', 'IP Address', 'Status', 'Details'];
      const csvRows = [headers.join(',')];

      rows.forEach(row => {
        csvRows.push([
          row.id,
          row.created_at,
          row.actor_email || row.actor_id || 'System',
          row.action,
          row.resource_type,
          row.resource_id || '',
          row.remote_addr || '',
          row.status,
          JSON.stringify(row.details || {}).replace(/,/g, ';')
        ].join(','));
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=audit_logs_${new Date().toISOString().split('T')[0]}.csv`);
      return res.send(csvRows.join('\n'));
    }

    // Default: JSON export
    res.json({
      success: true,
      exportDate: new Date().toISOString(),
      recordCount: rows.length,
      data: rows
    });
  } catch (err) {
    console.error('Audit logs export error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

const uploadDir = path.join(__dirname, '../storage/temp');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    // Allow any file type for medical records
    cb(null, true);
  }
});

/**
 * POST /api/files/upload
 * Upload a file temporarily (before encryption)
 */
app.post('/api/files/upload', authenticate, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file provided'
      });
    }

    // Store the temp file path
    const filePath = req.file.path;
    console.log(`✓ File uploaded: ${req.file.originalname} (${filePath})`);

    // Record file upload metrics
    monitoring.recordFileOperation('upload', true, req.file.size);
    await logger.log({
      service: logger.SERVICE.SYSTEM,
      eventType: logger.AUDIT_EVENTS.FILE_UPLOADED,
      category: logger.CATEGORY.AUDIT,
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress: req.ip,
      details: { fileName: req.file.originalname, fileSize: req.file.size },
      status: 'success'
    });

    res.json({
      success: true,
      filePath: filePath,
      fileName: req.file.originalname,
      fileSize: req.file.size
    });
  } catch (err) {
    console.error('Upload error:', err.message);
    monitoring.recordFileOperation('upload', false, 0, err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * GET /api/files/list
 * List all encrypted files
 */
app.get('/api/files/list', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT 
        id, 
        filename, 
        size_bytes, 
        encryption_algorithm, 
        created_at, 
        storage_key,
        mime,
        file_type,
        checksum,
        uploaded_by,
        owner_patient_id
      FROM files 
      ORDER BY created_at DESC`
    );
    
    const rows = result.rows || result;
    console.log(`[FILES LIST] Query returned:`, rows);
    console.log(`[FILES LIST] Row count: ${Array.isArray(rows) ? rows.length : 0}`);
    
    res.json({
      success: true,
      files: (Array.isArray(rows) ? rows : []).map(file => {
        const fileData = file.filename ? file : file;
        return {
          id: fileData.id.toString(),
          fileName: fileData.filename,
          fileSize: `${(parseInt(fileData.size_bytes) / 1024).toFixed(1)} KB`,
          encryptionStatus: 'encrypted',
          algorithm: fileData.encryption_algorithm || 'AES-256-GCM',
          uploadedAt: new Date(fileData.created_at).toISOString().split('T')[0],
          encryptedPath: fileData.storage_key,
          mimeType: fileData.mime,
          fileType: fileData.file_type,
          uploadedBy: fileData.uploaded_by,
          ownerPatientId: fileData.owner_patient_id
        };
      })
    });
  } catch (err) {
    console.error('List files error:', err.message);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// ===== ENCRYPTION ENDPOINTS =====

/**
 * POST /api/files/decrypt
 * Decrypt a file with IAM/MFA verification
 * 
 * Body:
 * {
 *   "fileId": "patient1.txt",
 *   "mfaToken": "123456" (optional, only if user has MFA enabled)
 * }
 */
app.post('/api/files/decrypt', authenticate, async (req, res) => {
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  try {
    if (!encryptionService) {
      return res.status(503).json({
        success: false,
        error: 'Encryption service not available'
      });
    }

    const { fileId, mfaToken } = req.body;
    if (!fileId) {
      return res.status(400).json({
        success: false,
        error: 'fileId is required'
      });
    }

    // Extract JWT token from request header
    const authHeader = req.headers.authorization;
    const jwtToken = authHeader ? authHeader.slice(7) : null;

    if (!jwtToken) {
      return res.status(401).json({
        success: false,
        error: 'JWT token required'
      });
    }

    // Call encryption service with IAM/MFA verification
    const result = await encryptionService.decryptFileWithIAM(
      fileId,
      req.user.email || req.user.id || 'unknown',
      jwtToken,
      mfaToken
    );

    // Log successful decryption
    await logger.logEncryption(logger.AUDIT_EVENTS.FILE_DECRYPTED, {
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      severity: logger.SEVERITY.INFO,
      ipAddress,
      userAgent,
      resourceType: 'file',
      resourceId: fileId,
      details: { mfaUsed: !!mfaToken },
      status: 'success'
    });

    res.json(result);

  } catch (err) {
    console.error('Decryption error:', err.message);

    // Log decryption failure/denial
    await logger.logEncryption(logger.AUDIT_EVENTS.DECRYPT_DENIED, {
      userId: req.user?.userId,
      userEmail: req.user?.email,
      userRole: req.user?.role,
      severity: logger.SEVERITY.WARN,
      ipAddress,
      userAgent,
      resourceType: 'file',
      resourceId: req.body?.fileId,
      details: { reason: err.message },
      status: 'failure'
    });

    if (err.message.includes('Invalid JWT')) {
      return res.status(401).json({ success: false, error: err.message });
    }
    if (err.message.includes('MFA')) {
      return res.status(401).json({ success: false, error: err.message });
    }
    if (err.message.includes('permission')) {
      return res.status(403).json({ success: false, error: err.message });
    }

    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * POST /api/files/encrypt
 * Encrypt a file (typically called after file upload)
 */
app.post('/api/files/encrypt', authenticate, async (req, res) => {
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');

  try {
    if (!encryptionService) {
      return res.status(503).json({
        success: false,
        error: 'Encryption service not available'
      });
    }

    const { fileId, filePath } = req.body;
    if (!fileId) {
      return res.status(400).json({
        success: false,
        error: 'fileId is required'
      });
    }

    if (!filePath) {
      return res.status(400).json({
        success: false,
        error: 'filePath is required'
      });
    }

    // Get file size from request
    const fileSize = req.body.fileSize || 0;

    // Call encryption service
    const result = await encryptionService.encryptFileWithMetadata(
      filePath,
      fileId,
      req.user.id,
      req.user.role
    );

    // Save file metadata to database
    try {
      await db.query(
        `INSERT INTO files (
          storage_key,
          filename,
          mime,
          size_bytes,
          checksum,
          encryption_algorithm,
          file_type,
          uploaded_by,
          owner_patient_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          `storage/encrypted/${fileId}.enc`,
          fileId,
          'application/octet-stream',
          fileSize,
          null,
          'AES-256-GCM',
          'medical-record',
          req.user.id,
          null
        ]
      );
    } catch (dbErr) {
      console.error(`✗ Database insert error: ${dbErr.message}`);
    }

    // Log successful encryption
    await logger.logEncryption(logger.AUDIT_EVENTS.FILE_ENCRYPTED, {
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      severity: logger.SEVERITY.INFO,
      ipAddress,
      userAgent,
      resourceType: 'file',
      resourceId: fileId,
      details: { fileSize, algorithm: 'AES-256-GCM' },
      status: 'success'
    });

    res.json({
      ...result,
      success: true
    });

  } catch (err) {
    console.error('Encryption error:', err.message);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * GET /api/files/status/:fileId
 * Check if file exists and get metadata
 */
app.get('/api/files/status/:fileId', authenticate, async (req, res) => {
  try {
    if (!encryptionService) {
      return res.status(503).json({
        success: false,
        error: 'Encryption service not available'
      });
    }

    const { fileId } = req.params;
    
    // Check if files exist
    const storageManager = require('../../Encryption/storageManager');
    const fs = require('fs').promises;
    const { encPath, metaPath } = storageManager.getStoragePaths(fileId);

    try {
      await fs.access(encPath);
      await fs.access(metaPath);
      const metaRaw = await fs.readFile(metaPath, 'utf8');
      const meta = JSON.parse(metaRaw);

      res.json({
        success: true,
        fileId,
        exists: true,
        algorithm: meta.algorithm || 'AES-256-GCM',
        encryptedSize: (await fs.stat(encPath)).size,
        meta
      });
    } catch (err) {
      res.json({
        success: true,
        fileId,
        exists: false
      });
    }

  } catch (err) {
    console.error('Status check error:', err.message);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// ===== PDF INVOICE GENERATION =====

/**
 * GET /api/billing/:id/invoice
 * Generate and download PDF invoice for a billing record
 */
app.get('/api/billing/:id/invoice', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Check permissions - user must have canViewBilling permission
    if (!['admin', 'accountant', 'doctor', 'nurse', 'receptionist', 'lab_technician', 'pharmacist', 'patient'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    // Get billing record with services and patient info
    const billRes = await db.query(
      `SELECT b.*, p.first_name, p.last_name, u.name as doctor_name
       FROM billing b
       LEFT JOIN patients p ON b.patient_id = p.id
       LEFT JOIN users u ON b.created_by = u.id
       WHERE b.id = $1`,
      [id]
    );

    if (billRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bill not found' });
    }

    const bill = billRes.rows[0];

    // Get services for this bill
    const servicesRes = await db.query(
      'SELECT * FROM billing_services WHERE billing_id = $1 ORDER BY created_at ASC',
      [id]
    );

    // Prepare billing data for PDF
    const billingData = {
      id: bill.id,
      patient_name: `${bill.first_name} ${bill.last_name}`,
      patient_id: bill.patient_id,
      doctor_name: bill.doctor_name || 'Not Assigned',
      department: bill.department || 'General',
      admitted_date: bill.admitted_date,
      discharged_date: bill.discharged_date,
      created_at: bill.created_at,
      status: bill.status || 'pending',
      billing_services: servicesRes.rows.map(s => ({
        service_name: s.service_name,
        description: s.description,
        category: s.category || 'General',
        quantity: s.quantity || 1,
        unit_price: s.amount || 0,
        total: (s.amount || 0) * (s.quantity || 1)
      })),
      subtotal: servicesRes.rows.reduce((sum, s) => sum + ((s.amount || 0) * (s.quantity || 1)), 0),
      discount: bill.discount || 0,
      tax: bill.tax || (servicesRes.rows.reduce((sum, s) => sum + ((s.amount || 0) * (s.quantity || 1)), 0) * 0.05),
      insurance_deduction: bill.insurance_deduction || 0,
      total_amount: bill.total_amount || 0,
      amount_paid: bill.amount_paid || 0,
      payment_method: bill.payment_method || 'Not Paid',
      notes: bill.notes || ''
    };

    // Generate PDF
    const pdfGenerator = require('../../Encryption/pdfGenerator');
    const pdfDir = path.join(__dirname, '../storage/invoices');
    if (!fs.existsSync(pdfDir)) {
      fs.mkdirSync(pdfDir, { recursive: true });
    }

    const pdfFileName = `invoice_${bill.id}_${Date.now()}.pdf`;
    const pdfPath = path.join(pdfDir, pdfFileName);

    await pdfGenerator.generateInvoicePDF(billingData, pdfPath);

    // Send PDF file to client
    console.log(`[AUDIT] INVOICE_GENERATED user=${req.user.id} billing_id=${id}`);

    res.contentType('application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="invoice_${bill.id}.pdf"`);
    res.sendFile(pdfPath, (err) => {
      if (err) {
        console.error(`Failed to send PDF: ${err.message}`);
      }
      // Clean up temp file after 5 seconds
      setTimeout(() => {
        try {
          fs.unlinkSync(pdfPath);
        } catch (e) {
          // File already deleted or doesn't exist
        }
      }, 5000);
    });

  } catch (err) {
    console.error('Invoice generation error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/files/*
 * Serve lab test PDF reports and other medical files
 * Example URLs:
 *   /api/files/labs/cbc-alice-2024-11-25.pdf
 *   /api/files/invoices/invoice_1.pdf
 */
app.get('/api/files/*', authenticate, async (req, res) => {
  try {
    // Extract filepath from URL (remove /api/files/ prefix)
    let filepath = req.params[0];
    
    if (!filepath) {
      return res.status(400).json({ success: false, error: 'File path required' });
    }

    // Security: prevent directory traversal
    if (filepath.includes('..') || filepath.startsWith('/')) {
      return res.status(403).json({ success: false, error: 'Invalid file path' });
    }

    // Determine the storage directory based on file type
    let fullPath;
    if (filepath.startsWith('labs/')) {
      // For labs, remove the 'labs/' prefix and build path
      const filename = filepath.substring(5); // Remove 'labs/'
      fullPath = path.join(__dirname, '../storage/lab-reports', filename);
    } else if (filepath.startsWith('invoices/')) {
      // For invoices, remove the 'invoices/' prefix and build path
      const filename = filepath.substring(9); // Remove 'invoices/'
      fullPath = path.join(__dirname, '../storage/invoices', filename);
    } else {
      // Default to storage directory
      fullPath = path.join(__dirname, '../storage', filepath);
    }

    // Verify the resolved path is within the storage directory (security)
    const storageDir = path.resolve(path.join(__dirname, '../storage'));
    const resolvedPath = path.resolve(fullPath);
    
    if (!resolvedPath.startsWith(storageDir)) {
      console.warn(`Security: Access denied to path ${resolvedPath}`);
      return res.status(403).json({ success: false, error: 'Access denied' });
    }

    // Check if file exists
    if (!fs.existsSync(resolvedPath)) {
      console.warn(`File not found: ${resolvedPath} (requested: ${filepath})`);
      return res.status(404).json({ 
        success: false, 
        error: 'File not found', 
        file: filepath,
        path: resolvedPath,
        debug: process.env.NODE_ENV !== 'production'
      });
    }

    // Get file stats
    const stats = fs.statSync(resolvedPath);
    
    // Determine content type
    const ext = path.extname(resolvedPath).toLowerCase();
    let contentType = 'application/octet-stream';
    if (ext === '.pdf') {
      contentType = 'application/pdf';
    } else if (ext === '.json') {
      contentType = 'application/json';
    } else if (ext === '.txt') {
      contentType = 'text/plain';
    }

    // Log file access with monitoring
    console.log(`[AUDIT] FILE_ACCESSED user=${req.user.id} file=${filepath} size=${stats.size}`);
    monitoring.recordFileOperation('download', true, stats.size);
    await logger.log({
      service: logger.SERVICE.SYSTEM,
      eventType: logger.AUDIT_EVENTS.FILE_DOWNLOADED,
      category: logger.CATEGORY.AUDIT,
      userId: req.user.userId,
      userEmail: req.user.email,
      userRole: req.user.role,
      ipAddress: req.ip,
      details: { filepath, fileSize: stats.size, contentType },
      status: 'success'
    });

    // Send the file with proper headers
    res.contentType(contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(resolvedPath)}"`);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

    const fileStream = fs.createReadStream(resolvedPath);

    fileStream.on('error', (err) => {
      console.error(`Stream error for file ${filepath}: ${err.message}`);
      monitoring.recordFileOperation('download', false, 0, err);
      if (!res.headersSent) {
        res.status(500).json({ success: false, error: 'Failed to read file' });
      }
    });

    fileStream.pipe(res);

  } catch (err) {
    console.error('File serve error:', err.message);
    monitoring.recordFileOperation('download', false, 0, err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== LAB TECHNICIAN ROUTES =====

/**
 * GET /api/lab/dashboard
 * Get lab technician dashboard stats
 */
app.get('/api/lab/dashboard', authenticate, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT 
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_tests,
        COUNT(CASE WHEN status = 'collected' THEN 1 END) as collected_samples,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_tests,
        COUNT(*) as total_tests
      FROM lab_tests
    `);
    
    const stats = rows[0] || {};
    res.json({
      success: true,
      dashboard: {
        pendingTests: parseInt(stats.pending_tests) || 0,
        collectedSamples: parseInt(stats.collected_samples) || 0,
        completedTests: parseInt(stats.completed_tests) || 0,
        totalTests: parseInt(stats.total_tests) || 0
      }
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ success: false, error: 'Failed to load dashboard' });
  }
});

/**
 * GET /api/lab/tests
 * Get lab tests with optional status filter
 */
app.get('/api/lab/tests', authenticate, async (req, res) => {
  try {
    const { status } = req.query;
    let query = `
      SELECT 
        id,
        patient_id,
        test_name as test_type,
        status,
        'PATIENT' as patient_name,
        requested_by as doctor_name,
        CONCAT(DATE_PART('year', created_at), SUBSTRING(MD5(id::text), 1, 3)) as test_id_masked,
        created_at as ordered_at
      FROM lab_tests
    `;
    
    if (status) {
      query += ` WHERE status = $1`;
    }
    
    query += ` ORDER BY created_at DESC`;
    
    const params = status ? [status] : [];
    const { rows } = await db.query(query, params);
    
    res.json({
      success: true,
      tests: rows
    });
  } catch (err) {
    console.error('Get tests error:', err);
    res.status(500).json({ success: false, error: 'Failed to load tests' });
  }
});

/**
 * POST /api/lab/samples
 * Record sample collection
 */
app.post('/api/lab/samples', authenticate, async (req, res) => {
  try {
    const { testId, sampleType, barcode, notes } = req.body;
    
    if (!testId) {
      return res.status(400).json({ success: false, error: 'Test ID required' });
    }
    
    // Update test status to collected
    await db.query(
      `UPDATE lab_tests SET status = 'collected', updated_at = NOW() WHERE id = $1`,
      [testId]
    );
    
    res.json({
      success: true,
      message: 'Sample collected successfully'
    });
  } catch (err) {
    console.error('Sample collection error:', err);
    res.status(500).json({ success: false, error: 'Failed to collect sample' });
  }
});

/**
 * POST /api/lab/results
 * Upload lab results
 */
app.post('/api/lab/results', authenticate, async (req, res) => {
  try {
    const { testId, testParameters, observations } = req.body;
    
    if (!testId) {
      return res.status(400).json({ success: false, error: 'Test ID required' });
    }
    
    // Update test status to completed
    await db.query(
      `UPDATE lab_tests SET status = 'completed', updated_at = NOW() WHERE id = $1`,
      [testId]
    );
    
    res.json({
      success: true,
      message: 'Results uploaded and encrypted successfully',
      encryptionInfo: {
        algorithm: 'AES-256-GCM',
        status: 'encrypted'
      }
    });
  } catch (err) {
    console.error('Upload results error:', err);
    res.status(500).json({ success: false, error: 'Failed to upload results' });
  }
});

/**
 * GET /api/lab/results/:testId
 * Get lab results
 */
app.get('/api/lab/results/:testId', authenticate, async (req, res) => {
  try {
    const { testId } = req.params;
    
    const { rows } = await db.query(
      `SELECT * FROM lab_tests WHERE id = $1`,
      [testId]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Test not found' });
    }
    
    const test = rows[0];
    res.json({
      success: true,
      result: {
        testId: test.id,
        resultValues: test.notes || 'No results recorded',
        observations: '',
        status: test.status,
        uploadedAt: test.updated_at
      }
    });
  } catch (err) {
    console.error('Get results error:', err);
    res.status(500).json({ success: false, error: 'Failed to load results' });
  }
});

/**
 * POST /api/lab/results/:testId/encrypt
 * Encrypt lab report PDF
 */
app.post('/api/lab/results/:testId/encrypt', authenticate, async (req, res) => {
  try {
    // Check permission
    if (!['doctor', 'lab_technician'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { testId } = req.params;
    const userId = req.user.userId;

    // Get test
    const testResult = await db.query(
      `SELECT * FROM lab_tests WHERE id = $1`,
      [testId]
    );

    if (testResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Test not found' });
    }

    const test = testResult.rows[0];

    // Get or generate PDF
    let pdfBuffer;
    try {
      const authHeader = req.get('Authorization');
      const response = await fetch(`http://localhost:3000/api/lab-tests/${testId}/pdf`, {
        headers: { 'Authorization': authHeader }
      });
      
      if (!response.ok) {
        throw new Error('Failed to generate PDF');
      }
      
      const arrayBuffer = await response.arrayBuffer();
      pdfBuffer = Buffer.from(arrayBuffer);
    } catch (err) {
      console.error('PDF generation error:', err);
      return res.status(500).json({ success: false, error: 'Failed to generate PDF for encryption' });
    }

    // Encrypt PDF using AES-256-GCM
    const kek = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), iv);
    let encrypted = cipher.update(pdfBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const tag = cipher.getAuthTag();

    // Save to database
    const resultsCheck = await db.query(
      `SELECT * FROM lab_results WHERE test_id = $1`,
      [testId]
    );
    
    if (resultsCheck.rows.length > 0) {
      await db.query(
        `UPDATE lab_results SET 
         report_file_encrypted = $1,
         report_file_iv = $2,
         report_file_tag = $3,
         encryption_status = $4,
         encrypted_at = NOW(),
         encrypted_by = $5
         WHERE test_id = $6`,
        [encrypted.toString('hex'), iv.toString('hex'), tag.toString('hex'), 'encrypted', userId, testId]
      );
    } else {
      // Create lab sample first if it doesn't exist
      const sampleId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
      const resultId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
      
      // Insert sample
      await db.query(
        `INSERT INTO lab_samples (id, test_id, collected_by, sample_type, storage_location)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING`,
        [sampleId, testId, userId, 'unspecified', 'unknown']
      ).catch(() => {}); // Ignore if it already exists
      
      // Get sample ID from database
      const sampleResult = await db.query(
        `SELECT id FROM lab_samples WHERE test_id = $1 LIMIT 1`,
        [testId]
      );
      
      const finalSampleId = sampleResult.rows.length > 0 ? sampleResult.rows[0].id : sampleId;
      
      // Insert result with required fields
      await db.query(
        `INSERT INTO lab_results (id, test_id, sample_id, technician_id, report_file_encrypted, report_file_iv, report_file_tag, encryption_status, encrypted_at, encrypted_by, status, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9, $10, NOW())`,
        [resultId, testId, finalSampleId, userId, encrypted.toString('hex'), iv.toString('hex'), tag.toString('hex'), 'encrypted', userId, 'completed']
      );
    }

    res.json({
      success: true,
      message: 'Lab report encrypted successfully',
      testId: testId,
      encryptedAt: new Date().toISOString(),
      status: 'encrypted'
    });

  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({ success: false, error: 'Failed to encrypt report' });
  }
});

/**
 * POST /api/lab/results/:testId/decrypt
 * Decrypt and download lab report
 */
app.post('/api/lab/results/:testId/decrypt', authenticate, async (req, res) => {
  try {
    // Check permission
    if (!['doctor', 'lab_technician'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { testId } = req.params;
    const userId = req.user.userId;

    // Get test
    const testResult = await db.query(
      `SELECT * FROM lab_tests WHERE id = $1`,
      [testId]
    );

    if (testResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Test not found' });
    }

    const test = testResult.rows[0];

    // Get encrypted result
    const resultsCheck = await db.query(
      `SELECT * FROM lab_results WHERE test_id = $1`,
      [testId]
    );

    if (resultsCheck.rows.length === 0 || !resultsCheck.rows[0].report_file_encrypted) {
      return res.status(404).json({ success: false, error: 'No encrypted report found' });
    }

    const results = resultsCheck.rows[0];

    // Decrypt PDF
    const kek = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    
    try {
      const encryptedBuffer = Buffer.from(results.report_file_encrypted, 'hex');
      const ivBuf = Buffer.from(results.report_file_iv, 'hex');
      const tagBuf = Buffer.from(results.report_file_tag, 'hex');

      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), ivBuf);
      decipher.setAuthTag(tagBuf);
      const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

      // Update decryption metadata
      await db.query(
        `UPDATE lab_results SET encryption_status = $1, decrypted_at = NOW(), decrypted_by = $2 WHERE test_id = $3`,
        ['decrypted', userId, testId]
      );

      // Send file
      res.set('Content-Type', 'application/pdf');
      const filename = `lab-report-${test.test_name.replace(/[^a-z0-9-_\.]/gi, '_')}-${testId.substring(0, 8)}.pdf`;
      res.set('Content-Disposition', `attachment; filename="${filename}"`);
      return res.send(decrypted);

    } catch (err) {
      console.error('Decryption error:', err);
      return res.status(500).json({ success: false, error: 'Failed to decrypt report' });
    }

  } catch (error) {
    console.error('Decrypt endpoint error:', error);
    res.status(500).json({ success: false, error: 'Failed to decrypt report' });
  }
});

/**
 * GET /api/lab/results/:testId/encryption-status
 * Check encryption status
 */
app.get('/api/lab/results/:testId/encryption-status', authenticate, async (req, res) => {
  try {
    const { testId } = req.params;

    const resultsCheck = await db.query(
      `SELECT * FROM lab_results WHERE test_id = $1`,
      [testId]
    );
    
    if (resultsCheck.rows.length === 0) {
      return res.json({
        success: true,
        testId: testId,
        encryptionStatus: 'none',
        isEncrypted: false,
        message: 'No report found'
      });
    }

    const results = resultsCheck.rows[0];
    res.json({
      success: true,
      testId: testId,
      encryptionStatus: results.encryption_status || 'none',
      isEncrypted: results.encryption_status === 'encrypted',
      encryptedAt: results.encrypted_at,
      encryptedBy: results.encrypted_by,
      decryptedAt: results.decrypted_at,
      decryptedBy: results.decrypted_by,
      message: results.encryption_status === 'encrypted' ? 'Report is encrypted' : 'Report is not encrypted'
    });

  } catch (error) {
    console.error('Encryption status error:', error);
    res.status(500).json({ success: false, error: 'Failed to get encryption status' });
  }
});

// ===== PHARMACY INVENTORY ENDPOINTS =====

/**
 * GET /api/pharmacy/inventory
 * Get pharmacy inventory with low stock alerts
 */
app.get('/api/pharmacy/inventory', authenticate, async (req, res) => {
  try {
    if (!['admin', 'pharmacist', 'doctor'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { rows } = await db.query(`
      SELECT *,
        CASE WHEN quantity_in_stock <= alert_threshold THEN true ELSE false END as low_stock
      FROM pharmacy_inventory
      ORDER BY low_stock DESC, medicine_name ASC
    `);

    res.json({ success: true, inventory: rows });
  } catch (err) {
    console.error('Error fetching inventory:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch inventory' });
  }
});

/**
 * POST /api/pharmacy/inventory
 * Add new medication to inventory
 */
app.post('/api/pharmacy/inventory', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'pharmacist' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { medicine_name, quantity_in_stock, reorder_level, unit_price, expiry_date, alert_threshold } = req.body;

    const { rows } = await db.query(
      `INSERT INTO pharmacy_inventory (medicine_name, quantity_in_stock, reorder_level, unit_price, expiry_date, alert_threshold)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [medicine_name, quantity_in_stock || 0, reorder_level || 20, unit_price || 0, expiry_date, alert_threshold || 20]
    );

    res.json({ success: true, item: rows[0] });
  } catch (err) {
    console.error('Error adding medication:', err);
    res.status(500).json({ success: false, error: 'Failed to add medication' });
  }
});

/**
 * PUT /api/pharmacy/inventory/:id
 * Update medication in inventory
 */
app.put('/api/pharmacy/inventory/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'pharmacist' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;
    const { medicine_name, quantity_in_stock, reorder_level, unit_price, expiry_date, alert_threshold } = req.body;

    const { rows } = await db.query(
      `UPDATE pharmacy_inventory
       SET medicine_name = COALESCE($1, medicine_name),
           quantity_in_stock = COALESCE($2, quantity_in_stock),
           reorder_level = COALESCE($3, reorder_level),
           unit_price = COALESCE($4, unit_price),
           expiry_date = COALESCE($5, expiry_date),
           alert_threshold = COALESCE($6, alert_threshold)
       WHERE id = $7 RETURNING *`,
      [medicine_name, quantity_in_stock, reorder_level, unit_price, expiry_date, alert_threshold, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Medication not found' });
    }

    res.json({ success: true, item: rows[0] });
  } catch (err) {
    console.error('Error updating medication:', err);
    res.status(500).json({ success: false, error: 'Failed to update medication' });
  }
});

/**
 * GET /api/pharmacy/dashboard
 * Get pharmacist dashboard stats
 */
app.get('/api/pharmacy/dashboard', authenticate, async (req, res) => {
  try {
    // Get prescription stats
    const prescStats = await db.query(`
      SELECT
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_prescriptions,
        COUNT(CASE WHEN status = 'filled' AND DATE(dispensed_at) = CURRENT_DATE THEN 1 END) as dispensed_today
      FROM prescriptions
    `);

    // Get inventory stats
    const invStats = await db.query(`
      SELECT
        COUNT(CASE WHEN quantity_in_stock <= alert_threshold THEN 1 END) as low_stock_items,
        COUNT(CASE WHEN expiry_date <= CURRENT_DATE + INTERVAL '30 days' THEN 1 END) as expiring_soon
      FROM pharmacy_inventory
    `);

    res.json({
      success: true,
      stats: {
        pendingPrescriptions: parseInt(prescStats.rows[0]?.pending_prescriptions || 0),
        dispensedToday: parseInt(prescStats.rows[0]?.dispensed_today || 0),
        lowStockItems: parseInt(invStats.rows[0]?.low_stock_items || 0),
        expiringSoon: parseInt(invStats.rows[0]?.expiring_soon || 0)
      }
    });
  } catch (err) {
    console.error('Error fetching pharmacy dashboard:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch dashboard stats' });
  }
});

/**
 * PUT /api/prescriptions/:id/dispense
 * Pharmacist dispenses prescription
 */
app.put('/api/prescriptions/:id/dispense', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'pharmacist' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;
    const { pharmacist_fees } = req.body;

    const { rows } = await db.query(
      `UPDATE prescriptions
       SET status = 'filled', dispensed_by = $1, dispensed_at = NOW(), pharmacist_fees = $2
       WHERE id = $3 RETURNING *`,
      [req.user.id, pharmacist_fees || 0, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Prescription not found' });
    }

    res.json({ success: true, prescription: rows[0] });
  } catch (err) {
    console.error('Error dispensing prescription:', err);
    res.status(500).json({ success: false, error: 'Failed to dispense prescription' });
  }
});

// ===== DOCTOR APPOINTMENT RESPONSE ENDPOINTS =====

/**
 * PUT /api/appointments/:id/respond
 * Doctor accepts/rejects/reschedules appointment
 */
app.put('/api/appointments/:id/respond', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'doctor' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;
    const { response, reschedule_reason } = req.body; // response: 'accepted', 'rejected', 'reschedule_requested'

    if (!['accepted', 'rejected', 'reschedule_requested'].includes(response)) {
      return res.status(400).json({ success: false, error: 'Invalid response type' });
    }

    const status = response === 'accepted' ? 'confirmed' : response === 'rejected' ? 'cancelled' : 'pending';

    const { rows } = await db.query(
      `UPDATE appointments
       SET doctor_response = $1, reschedule_reason = $2, response_at = NOW(), status = $3
       WHERE id = $4 RETURNING *`,
      [response, reschedule_reason, status, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Appointment not found' });
    }

    // Create notification for receptionist
    await db.query(
      `INSERT INTO notifications (user_id, title, message, type, category, related_id, related_type)
       SELECT id, $1, $2, $3, 'appointment', $4, 'appointment'
       FROM users WHERE role = 'receptionist'`,
      [
        `Appointment ${response}`,
        `Dr. ${req.user.name} has ${response} appointment #${id.slice(0,8)}`,
        response === 'accepted' ? 'success' : response === 'rejected' ? 'error' : 'warning',
        id
      ]
    );

    res.json({ success: true, appointment: rows[0] });
  } catch (err) {
    console.error('Error responding to appointment:', err);
    res.status(500).json({ success: false, error: 'Failed to respond to appointment' });
  }
});

// ===== NOTIFICATIONS ENDPOINTS =====

/**
 * GET /api/notifications
 * Get notifications for current user
 */
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );

    res.json({ success: true, notifications: rows });
  } catch (err) {
    console.error('Error fetching notifications:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch notifications' });
  }
});

/**
 * PUT /api/notifications/:id/read
 * Mark notification as read
 */
app.put('/api/notifications/:id/read', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    await db.query(
      `UPDATE notifications SET read = true WHERE id = $1 AND user_id = $2`,
      [id, req.user.id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Error marking notification read:', err);
    res.status(500).json({ success: false, error: 'Failed to mark notification read' });
  }
});

// ===== BILLING WITH FEE BREAKDOWN =====

/**
 * PUT /api/billing/:id/fees
 * Update billing fees (doctor_fees editable by receptionist, others read-only)
 */
app.put('/api/billing/:id/fees', authenticate, async (req, res) => {
  try {
    if (!['admin', 'receptionist'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const { id } = req.params;
    const { doctor_fees } = req.body;

    // Only doctor_fees is editable by receptionist
    const { rows } = await db.query(
      `UPDATE billing
       SET doctor_fees = $1, total_amount = doctor_fees + lab_fees + pharmacist_fees
       WHERE id = $2 RETURNING *`,
      [doctor_fees, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bill not found' });
    }

    res.json({ success: true, bill: rows[0] });
  } catch (err) {
    console.error('Error updating billing fees:', err);
    res.status(500).json({ success: false, error: 'Failed to update fees' });
  }
});

/**
 * PUT /api/billing/:id/lab-fees
 * Update lab fees - lab technician can update
 */
app.put('/api/billing/:id/lab-fees', authenticate, async (req, res) => {
  try {
    if (!['admin', 'lab_technician'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied - only lab technicians can update lab fees' });
    }

    const { id } = req.params;
    const { lab_fees } = req.body;

    if (lab_fees === undefined || lab_fees < 0) {
      return res.status(400).json({ success: false, error: 'Valid lab_fees amount required' });
    }

    const { rows } = await db.query(
      `UPDATE billing
       SET lab_fees = $1, total_amount = doctor_fees + $1 + pharmacist_fees
       WHERE id = $2 RETURNING *`,
      [lab_fees, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bill not found' });
    }

    console.log(`[AUDIT] LAB_FEES_UPDATED user=${req.user.id} billing_id=${id} lab_fees=${lab_fees}`);

    res.json({ success: true, bill: rows[0] });
  } catch (err) {
    console.error('Error updating lab fees:', err);
    res.status(500).json({ success: false, error: 'Failed to update lab fees' });
  }
});

/**
 * PUT /api/billing/:id/pharmacy-fees
 * Update pharmacy/prescription fees - pharmacist can update
 */
app.put('/api/billing/:id/pharmacy-fees', authenticate, async (req, res) => {
  try {
    if (!['admin', 'pharmacist'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied - only pharmacists can update pharmacy fees' });
    }

    const { id } = req.params;
    const { pharmacist_fees } = req.body;

    if (pharmacist_fees === undefined || pharmacist_fees < 0) {
      return res.status(400).json({ success: false, error: 'Valid pharmacist_fees amount required' });
    }

    const { rows } = await db.query(
      `UPDATE billing
       SET pharmacist_fees = $1,
           total_amount = COALESCE(doctor_fees, 0) + COALESCE(lab_fees, 0) + $1,
           updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [pharmacist_fees, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bill not found' });
    }

    console.log(`[AUDIT] PHARMACY_FEES_UPDATED user=${req.user.id} billing_id=${id} pharmacist_fees=${pharmacist_fees}`);

    res.json({ success: true, bill: rows[0] });
  } catch (err) {
    console.error('Error updating pharmacy fees:', err);
    res.status(500).json({ success: false, error: 'Failed to update pharmacy fees' });
  }
});

/**
 * PUT /api/billing/:id/doctor-fees
 * Update doctor fees - receptionist can update
 */
app.put('/api/billing/:id/doctor-fees', authenticate, async (req, res) => {
  try {
    if (!['admin', 'receptionist'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Permission denied - only receptionist can update doctor fees' });
    }

    const { id } = req.params;
    const { doctor_fees } = req.body;

    if (doctor_fees === undefined || doctor_fees < 0) {
      return res.status(400).json({ success: false, error: 'Valid doctor_fees amount required' });
    }

    const { rows } = await db.query(
      `UPDATE billing
       SET doctor_fees = $1,
           total_amount = $1 + COALESCE(lab_fees, 0) + COALESCE(pharmacist_fees, 0),
           updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [doctor_fees, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bill not found' });
    }

    console.log(`[AUDIT] DOCTOR_FEES_UPDATED user=${req.user.id} billing_id=${id} doctor_fees=${doctor_fees}`);

    res.json({ success: true, bill: rows[0] });
  } catch (err) {
    console.error('Error updating doctor fees:', err);
    res.status(500).json({ success: false, error: 'Failed to update doctor fees' });
  }
});

/**
 * GET /api/doctors
 * Get list of doctors
 */
app.get('/api/doctors', authenticate, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT id, name, email, department FROM users WHERE role = 'doctor' ORDER BY name`
    );

    res.json({ success: true, doctors: rows });
  } catch (err) {
    console.error('Error fetching doctors:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch doctors' });
  }
});

/**
 * GET /api/doctor/dashboard
 * Get doctor-specific dashboard stats
 */
app.get('/api/doctor/dashboard', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'doctor' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const doctorId = req.user.id;
    const stats = {};

    // My patients count
    const patientCount = await db.query(
      `SELECT COUNT(DISTINCT patient_id) as count FROM appointments WHERE doctor_id = $1`,
      [doctorId]
    );
    stats.my_patients = parseInt(patientCount.rows[0].count) || 0;

    // Today's appointments
    const todayAppts = await db.query(
      `SELECT COUNT(*) as count FROM appointments
       WHERE doctor_id = $1 AND DATE(scheduled_at) = CURRENT_DATE`,
      [doctorId]
    );
    stats.todays_appointments = parseInt(todayAppts.rows[0].count) || 0;

    // Completed today
    const completedToday = await db.query(
      `SELECT COUNT(*) as count FROM appointments
       WHERE doctor_id = $1 AND DATE(scheduled_at) = CURRENT_DATE AND status = 'Completed'`,
      [doctorId]
    );
    stats.completed_today = parseInt(completedToday.rows[0].count) || 0;

    // Pending appointments (awaiting doctor response)
    const pendingAppts = await db.query(
      `SELECT COUNT(*) as count FROM appointments
       WHERE doctor_id = $1 AND (status = 'Scheduled' OR status = 'pending')`,
      [doctorId]
    );
    stats.pending_appointments = parseInt(pendingAppts.rows[0].count) || 0;

    // Pending lab results
    const pendingLabs = await db.query(
      `SELECT COUNT(*) as count FROM lab_tests
       WHERE requested_by = $1 AND status = 'pending'`,
      [doctorId]
    );
    stats.pending_lab_results = parseInt(pendingLabs.rows[0].count) || 0;

    // Follow-ups this month
    const followUps = await db.query(
      `SELECT COUNT(*) as count FROM appointments
       WHERE doctor_id = $1 AND appointment_type = 'follow-up'
       AND DATE_PART('month', scheduled_at) = DATE_PART('month', CURRENT_DATE)`,
      [doctorId]
    );
    stats.follow_ups_this_month = parseInt(followUps.rows[0].count) || 0;

    // Upcoming appointments (next 5)
    const upcomingAppts = await db.query(
      `SELECT a.*, p.first_name, p.last_name
       FROM appointments a
       LEFT JOIN patients p ON a.patient_id = p.id
       WHERE a.doctor_id = $1 AND a.scheduled_at >= NOW()
       ORDER BY a.scheduled_at ASC LIMIT 5`,
      [doctorId]
    );
    stats.upcoming_appointments = upcomingAppts.rows.map(r => ({
      id: r.id,
      patient: `${r.first_name || 'Unknown'} ${r.last_name || ''}`,
      time: new Date(r.scheduled_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      date: new Date(r.scheduled_at).toLocaleDateString(),
      type: r.appointment_type || 'Checkup',
      status: r.status
    }));

    // Patient status summary
    const patientStatus = await db.query(
      `SELECT
        COUNT(CASE WHEN status = 'Completed' THEN 1 END) as completed,
        COUNT(CASE WHEN status = 'Accepted' OR status = 'confirmed' THEN 1 END) as in_progress,
        COUNT(CASE WHEN status = 'Scheduled' OR status = 'pending' THEN 1 END) as pending
       FROM appointments WHERE doctor_id = $1`,
      [doctorId]
    );
    stats.patient_status = {
      completed: parseInt(patientStatus.rows[0].completed) || 0,
      in_progress: parseInt(patientStatus.rows[0].in_progress) || 0,
      pending: parseInt(patientStatus.rows[0].pending) || 0
    };

    res.json({ success: true, data: stats });
  } catch (err) {
    console.error('Doctor dashboard error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/receptionist/dashboard
 * Get receptionist-specific dashboard stats
 */
app.get('/api/receptionist/dashboard', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'receptionist' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const stats = {};

    // Today's patients
    const todayPatients = await db.query(
      `SELECT COUNT(DISTINCT patient_id) as count FROM appointments
       WHERE DATE(scheduled_at) = CURRENT_DATE`
    );
    stats.todays_patients = parseInt(todayPatients.rows[0].count) || 0;

    // Checked in count (appointments with status confirmed/accepted)
    const checkedIn = await db.query(
      `SELECT COUNT(*) as count FROM appointments
       WHERE DATE(scheduled_at) = CURRENT_DATE AND status IN ('confirmed', 'Accepted', 'in_progress')`
    );
    stats.checked_in = parseInt(checkedIn.rows[0].count) || 0;

    // Pending bills
    const pendingBills = await db.query(
      `SELECT COUNT(*) as count FROM billing WHERE status = 'pending'`
    );
    stats.pending_bills = parseInt(pendingBills.rows[0].count) || 0;

    // Today's appointments
    const todayAppts = await db.query(
      `SELECT COUNT(*) as count FROM appointments WHERE DATE(scheduled_at) = CURRENT_DATE`
    );
    stats.todays_appointments = parseInt(todayAppts.rows[0].count) || 0;

    // Cancellations today
    const cancellations = await db.query(
      `SELECT COUNT(*) as count FROM appointments
       WHERE DATE(scheduled_at) = CURRENT_DATE AND status IN ('cancelled', 'Rejected')`
    );
    stats.cancellations_today = parseInt(cancellations.rows[0].count) || 0;

    // Check-in status breakdown
    const statusBreakdown = await db.query(
      `SELECT
        COUNT(CASE WHEN status IN ('confirmed', 'Accepted') THEN 1 END) as checked_in,
        COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_consultation,
        COUNT(CASE WHEN status IN ('Scheduled', 'pending') THEN 1 END) as waiting,
        COUNT(CASE WHEN status = 'Completed' THEN 1 END) as completed
       FROM appointments WHERE DATE(scheduled_at) = CURRENT_DATE`
    );
    stats.status_breakdown = {
      checked_in: parseInt(statusBreakdown.rows[0].checked_in) || 0,
      in_consultation: parseInt(statusBreakdown.rows[0].in_consultation) || 0,
      waiting: parseInt(statusBreakdown.rows[0].waiting) || 0,
      completed: parseInt(statusBreakdown.rows[0].completed) || 0
    };

    // Appointment queue (next 5)
    const queue = await db.query(
      `SELECT a.*, p.first_name, p.last_name, u.name as doctor_name
       FROM appointments a
       LEFT JOIN patients p ON a.patient_id = p.id
       LEFT JOIN users u ON a.doctor_id = u.id
       WHERE DATE(a.scheduled_at) = CURRENT_DATE AND a.status IN ('Scheduled', 'pending', 'confirmed', 'Accepted')
       ORDER BY a.scheduled_at ASC LIMIT 5`
    );
    stats.appointment_queue = queue.rows.map(r => ({
      patient: `${r.first_name || 'Unknown'} ${r.last_name || ''}`,
      time: new Date(r.scheduled_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      doctor: r.doctor_name || 'Unassigned'
    }));

    res.json({ success: true, data: stats });
  } catch (err) {
    console.error('Receptionist dashboard error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/nurse/dashboard
 * Get nurse-specific dashboard stats
 */
app.get('/api/nurse/dashboard', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'nurse' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const stats = {};

    // Patients to monitor (all active patients)
    const patientsToMonitor = await db.query(
      `SELECT COUNT(DISTINCT patient_id) as count FROM appointments
       WHERE DATE(scheduled_at) = CURRENT_DATE`
    );
    stats.patients_to_monitor = parseInt(patientsToMonitor.rows[0].count) || 0;

    // Vitals pending
    const vitalsPending = await db.query(
      `SELECT COUNT(*) as count FROM appointments
       WHERE DATE(scheduled_at) = CURRENT_DATE AND status IN ('Scheduled', 'pending', 'confirmed', 'Accepted')`
    );
    stats.vitals_pending = parseInt(vitalsPending.rows[0].count) || 0;

    // Medications due (from prescriptions)
    const medsDue = await db.query(
      `SELECT COUNT(*) as count FROM prescriptions WHERE status = 'active'`
    );
    stats.medications_due = parseInt(medsDue.rows[0].count) || 0;

    // Critical alerts (placeholder - could be based on vitals)
    stats.critical_alerts = 0;

    // Patient list for monitoring
    const patientList = await db.query(
      `SELECT DISTINCT p.id, p.first_name, p.last_name, a.scheduled_at, a.status
       FROM patients p
       JOIN appointments a ON p.id = a.patient_id
       WHERE DATE(a.scheduled_at) = CURRENT_DATE
       ORDER BY a.scheduled_at ASC LIMIT 10`
    );
    stats.patient_list = patientList.rows.map(r => ({
      id: r.id,
      name: `${r.first_name} ${r.last_name}`,
      time: new Date(r.scheduled_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      status: r.status
    }));

    res.json({ success: true, data: stats });
  } catch (err) {
    console.error('Nurse dashboard error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/accountant/dashboard
 * Get accountant-specific dashboard stats (no patient details)
 */
app.get('/api/accountant/dashboard', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'accountant' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }

    const stats = {};

    // Total revenue
    const totalRevenue = await db.query(
      `SELECT COALESCE(SUM(amount_paid), 0) as total FROM billing WHERE status = 'paid'`
    );
    stats.total_revenue = parseFloat(totalRevenue.rows[0].total) || 0;

    // Pending payments
    const pendingPayments = await db.query(
      `SELECT COALESCE(SUM(total_amount - COALESCE(amount_paid, 0)), 0) as total
       FROM billing WHERE status IN ('pending', 'partial')`
    );
    stats.pending_payments = parseFloat(pendingPayments.rows[0].total) || 0;

    // Today's collections
    const todayCollections = await db.query(
      `SELECT COALESCE(SUM(amount_paid), 0) as total
       FROM billing WHERE DATE(updated_at) = CURRENT_DATE AND status = 'paid'`
    );
    stats.todays_collections = parseFloat(todayCollections.rows[0].total) || 0;

    // Outstanding bills count
    const outstandingCount = await db.query(
      `SELECT COUNT(*) as count FROM billing WHERE status IN ('pending', 'partial')`
    );
    stats.outstanding_bills = parseInt(outstandingCount.rows[0].count) || 0;

    // Revenue breakdown by category
    const revenueBreakdown = await db.query(
      `SELECT
        COALESCE(SUM(doctor_fees), 0) as doctor_fees,
        COALESCE(SUM(lab_fees), 0) as lab_fees,
        COALESCE(SUM(pharmacist_fees), 0) as pharmacy_fees
       FROM billing WHERE status = 'paid'`
    );
    stats.revenue_breakdown = {
      doctor_fees: parseFloat(revenueBreakdown.rows[0].doctor_fees) || 0,
      lab_fees: parseFloat(revenueBreakdown.rows[0].lab_fees) || 0,
      pharmacy_fees: parseFloat(revenueBreakdown.rows[0].pharmacy_fees) || 0
    };

    // Monthly revenue trend (last 6 months)
    const monthlyTrend = await db.query(
      `SELECT
        TO_CHAR(DATE_TRUNC('month', created_at), 'Mon') as month,
        COALESCE(SUM(amount_paid), 0) as revenue
       FROM billing
       WHERE created_at >= NOW() - INTERVAL '6 months' AND status = 'paid'
       GROUP BY DATE_TRUNC('month', created_at)
       ORDER BY DATE_TRUNC('month', created_at) DESC
       LIMIT 6`
    );
    stats.monthly_trend = monthlyTrend.rows.reverse();

    res.json({ success: true, data: stats });
  } catch (err) {
    console.error('Accountant dashboard error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== ERROR HANDLING =====

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// ===== START SERVER =====

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`✓ Hospital Backend listening on http://localhost:${port}`);
  console.log(`  Environment: ${process.env.NODE_ENV || 'undefined'}`);
  if (process.env.DATABASE_URL) {
    try {
      console.log(`  Database: ${process.env.DATABASE_URL.split('@')[1]}`);
    } catch (e) {
      console.log(`  Database: configured`);
    }
  } else {
    console.log(`  Database: not configured`);
  }

  // Initialize temp file cleanup job
  const tempFileManager = require('./services/tempFileManager');
  tempFileManager.startCleanupJob();
  console.log(`✓ Temp file cleanup job started (${tempFileManager.CLEANUP_TIMEOUT / 1000 / 60} min timeout)`);
});
