/**
 * Security Monitoring Service
 *
 * Detects security anomalies and suspicious patterns:
 * - Excessive failed login attempts (brute force)
 * - Multiple decrypt requests within short time
 * - Same user accessing many patients rapidly
 * - IP accessing multiple user accounts
 * - JWT-related security events
 *
 * PHASE 2 INTEGRATION: Sends security events to central telemetry API
 * and CRITICAL alerts to the Response Controller for automated response.
 */

const winstonLogger = require('./winstonLogger');
const http = require('http');

// Phase 2 Integration Configuration
const PHASE2_CONFIG = {
  TELEMETRY_HOST: process.env.TELEMETRY_HOST || '172.20.0.100',
  TELEMETRY_PORT: process.env.TELEMETRY_PORT || 9090,
  RESPONSE_CONTROLLER_HOST: process.env.RESPONSE_CONTROLLER_HOST || '172.20.0.130',
  RESPONSE_CONTROLLER_PORT: process.env.RESPONSE_CONTROLLER_PORT || 4100,
  HOST_ID: process.env.HOST_ID || 'hospital-backend',
  ENABLED: process.env.PHASE2_INTEGRATION !== 'false' // Enabled by default
};

// Configuration thresholds
const THRESHOLDS = {
  MAX_LOGIN_FAILURES_PER_IP: 5,        // Per 15 minutes
  MAX_LOGIN_FAILURES_PER_USER: 3,       // Per 15 minutes
  MAX_DECRYPT_REQUESTS: 50,             // Per 5 minutes
  MAX_PATIENT_ACCESS_RATE: 20,          // Different patients per 5 minutes
  MAX_ACCOUNTS_PER_IP: 3,               // Different accounts from same IP per hour
  SUSPICIOUS_ACTIVITY_WINDOW: 15 * 60 * 1000, // 15 minutes in ms
  SHORT_WINDOW: 5 * 60 * 1000           // 5 minutes in ms
};

// In-memory tracking stores (would use Redis in production)
const trackingData = {
  loginFailuresByIP: new Map(),
  loginFailuresByUser: new Map(),
  decryptRequestsByUser: new Map(),
  patientAccessByUser: new Map(),
  accountsByIP: new Map(),
  blockedIPs: new Set(),
  alerts: []
};

// Clean up old entries periodically
setInterval(() => {
  const now = Date.now();
  cleanupOldEntries(trackingData.loginFailuresByIP, THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW);
  cleanupOldEntries(trackingData.loginFailuresByUser, THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW);
  cleanupOldEntries(trackingData.decryptRequestsByUser, THRESHOLDS.SHORT_WINDOW);
  cleanupOldEntries(trackingData.patientAccessByUser, THRESHOLDS.SHORT_WINDOW);
  cleanupOldEntries(trackingData.accountsByIP, 60 * 60 * 1000); // 1 hour
  
  // Keep only last 1000 alerts
  if (trackingData.alerts.length > 1000) {
    trackingData.alerts = trackingData.alerts.slice(-1000);
  }
}, 60 * 1000); // Run every minute

function cleanupOldEntries(map, maxAge) {
  const now = Date.now();
  for (const [key, entries] of map.entries()) {
    const filtered = entries.filter(e => now - e.timestamp < maxAge);
    if (filtered.length === 0) {
      map.delete(key);
    } else {
      map.set(key, filtered);
    }
  }
}

// ================== TRACKING FUNCTIONS ==================

function trackLoginFailure(ipAddress, email) {
  const now = Date.now();

  // Track by IP
  if (!trackingData.loginFailuresByIP.has(ipAddress)) {
    trackingData.loginFailuresByIP.set(ipAddress, []);
  }
  trackingData.loginFailuresByIP.get(ipAddress).push({ timestamp: now, email });

  // Track by user
  if (email) {
    if (!trackingData.loginFailuresByUser.has(email)) {
      trackingData.loginFailuresByUser.set(email, []);
    }
    trackingData.loginFailuresByUser.get(email).push({ timestamp: now, ipAddress });
  }

  // ===== PHASE 2 INTEGRATION: Send login failure telemetry =====
  sendTelemetryToPhase2('LOGIN_FAILURE', {
    ipAddress,
    email: email || 'unknown',
    timestamp: new Date(now).toISOString()
  });

  // Check thresholds
  checkLoginThresholds(ipAddress, email);
}

function trackDecryptRequest(userId, resourceId) {
  const now = Date.now();
  if (!trackingData.decryptRequestsByUser.has(userId)) {
    trackingData.decryptRequestsByUser.set(userId, []);
  }
  trackingData.decryptRequestsByUser.get(userId).push({ timestamp: now, resourceId });
  
  // Check threshold
  const recentRequests = getRecentEntries(trackingData.decryptRequestsByUser.get(userId), THRESHOLDS.SHORT_WINDOW);
  if (recentRequests.length > THRESHOLDS.MAX_DECRYPT_REQUESTS) {
    createAlert('HIGH_DECRYPT_RATE', 'warning', { userId, count: recentRequests.length });
  }
}

function trackPatientAccess(userId, patientId) {
  const now = Date.now();
  if (!trackingData.patientAccessByUser.has(userId)) {
    trackingData.patientAccessByUser.set(userId, []);
  }
  trackingData.patientAccessByUser.get(userId).push({ timestamp: now, patientId });
  
  // Check for rapid access to many different patients
  const recentAccesses = getRecentEntries(trackingData.patientAccessByUser.get(userId), THRESHOLDS.SHORT_WINDOW);
  const uniquePatients = new Set(recentAccesses.map(a => a.patientId));
  
  if (uniquePatients.size > THRESHOLDS.MAX_PATIENT_ACCESS_RATE) {
    createAlert('RAPID_PATIENT_ACCESS', 'warning', { 
      userId, 
      uniquePatientsCount: uniquePatients.size,
      timeWindowMinutes: THRESHOLDS.SHORT_WINDOW / 60000 
    });
  }
}

function trackAccountAccess(ipAddress, userId) {
  const now = Date.now();
  if (!trackingData.accountsByIP.has(ipAddress)) {
    trackingData.accountsByIP.set(ipAddress, []);
  }
  trackingData.accountsByIP.get(ipAddress).push({ timestamp: now, userId });
  
  // Check for multiple accounts from same IP
  const recentAccesses = getRecentEntries(trackingData.accountsByIP.get(ipAddress), 60 * 60 * 1000);
  const uniqueAccounts = new Set(recentAccesses.map(a => a.userId));
  
  if (uniqueAccounts.size > THRESHOLDS.MAX_ACCOUNTS_PER_IP) {
    createAlert('MULTIPLE_ACCOUNTS_SAME_IP', 'warning', { 
      ipAddress, 
      accountCount: uniqueAccounts.size 
    });
  }
}

// ================== HELPER FUNCTIONS ==================

function getRecentEntries(entries, maxAge) {
  if (!entries) return [];
  const now = Date.now();
  return entries.filter(e => now - e.timestamp < maxAge);
}

function checkLoginThresholds(ipAddress, email) {
  const ipFailures = getRecentEntries(
    trackingData.loginFailuresByIP.get(ipAddress), 
    THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW
  );
  
  if (ipFailures.length >= THRESHOLDS.MAX_LOGIN_FAILURES_PER_IP) {
    createAlert('BRUTE_FORCE_IP', 'critical', { ipAddress, failureCount: ipFailures.length });
    trackingData.blockedIPs.add(ipAddress);
  }
  
  if (email) {
    const userFailures = getRecentEntries(
      trackingData.loginFailuresByUser.get(email),
      THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW
    );
    if (userFailures.length >= THRESHOLDS.MAX_LOGIN_FAILURES_PER_USER) {
      createAlert('BRUTE_FORCE_USER', 'warning', { email, failureCount: userFailures.length });
    }
  }
}

// ================== PHASE 2 INTEGRATION ==================

/**
 * Send telemetry to Phase 2 central collector
 */
function sendTelemetryToPhase2(eventType, data) {
  if (!PHASE2_CONFIG.ENABLED) return;

  const telemetry = {
    hostId: PHASE2_CONFIG.HOST_ID,
    ts: new Date().toISOString(),
    source: 'backend-security-monitor',
    eventType: eventType,
    security: data,
    // Add net field for traffic-analyzer compatibility if IP-related
    ...(data.ipAddress && { net: { src: data.ipAddress, dst: PHASE2_CONFIG.HOST_ID } })
  };

  const postData = JSON.stringify(telemetry);
  const options = {
    hostname: PHASE2_CONFIG.TELEMETRY_HOST,
    port: PHASE2_CONFIG.TELEMETRY_PORT,
    path: '/ingest/telemetry',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    },
    timeout: 5000
  };

  const req = http.request(options, (res) => {
    if (res.statusCode === 200) {
      console.log(`[Phase2] Telemetry sent: ${eventType}`);
    }
  });

  req.on('error', (err) => {
    // Silently fail - don't break main app if Phase 2 is down
    console.warn(`[Phase2] Telemetry send failed: ${err.message}`);
  });

  req.on('timeout', () => {
    req.destroy();
  });

  req.write(postData);
  req.end();
}

/**
 * Send CRITICAL alert to Phase 2 Response Controller for automated action
 */
function sendAlertToResponseController(alertType, data) {
  if (!PHASE2_CONFIG.ENABLED) return;

  const alert = {
    severity: 'CRITICAL',
    event: alertType,
    hostId: data.hostId || PHASE2_CONFIG.HOST_ID,
    ts: new Date().toISOString(),
    source: 'backend-security-monitor',
    details: data
  };

  const postData = JSON.stringify(alert);
  const options = {
    hostname: PHASE2_CONFIG.RESPONSE_CONTROLLER_HOST,
    port: PHASE2_CONFIG.RESPONSE_CONTROLLER_PORT,
    path: '/alert',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    },
    timeout: 5000
  };

  const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      try {
        const response = JSON.parse(body);
        if (response.action === 'isolate') {
          console.log(`[Phase2] 🚨 Response Controller isolated host: ${response.hostId}`);
        }
      } catch (e) { /* ignore parse errors */ }
    });
  });

  req.on('error', (err) => {
    console.warn(`[Phase2] Alert send to controller failed: ${err.message}`);
  });

  req.on('timeout', () => {
    req.destroy();
  });

  req.write(postData);
  req.end();
}

// ================== ALERT SYSTEM ==================

function createAlert(alertType, severity, data) {
  const alert = {
    id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    type: alertType,
    severity, // 'info', 'warning', 'critical'
    timestamp: new Date().toISOString(),
    data,
    acknowledged: false
  };

  trackingData.alerts.push(alert);

  // Log to security log
  winstonLogger.logSecurity(`SECURITY_ALERT_${alertType}`, {
    alertId: alert.id,
    severity,
    details: data,
    ipAddress: data.ipAddress
  });

  // Console warning for critical alerts
  if (severity === 'critical') {
    console.error(`\x1b[31m[CRITICAL SECURITY ALERT]\x1b[0m ${alertType}:`, data);
  }

  // ===== PHASE 2 INTEGRATION =====
  // Send all alerts to telemetry
  sendTelemetryToPhase2(`SECURITY_ALERT_${alertType}`, {
    alertId: alert.id,
    alertType,
    severity,
    ...data
  });

  // Send CRITICAL alerts to Response Controller for automated action
  if (severity === 'critical') {
    sendAlertToResponseController(alertType, data);
  }

  return alert;
}

function getAlerts(filters = {}) {
  let alerts = trackingData.alerts;

  if (filters.severity) {
    alerts = alerts.filter(a => a.severity === filters.severity);
  }
  if (filters.type) {
    alerts = alerts.filter(a => a.type === filters.type);
  }
  if (filters.unacknowledged) {
    alerts = alerts.filter(a => !a.acknowledged);
  }
  if (filters.since) {
    const sinceDate = new Date(filters.since);
    alerts = alerts.filter(a => new Date(a.timestamp) > sinceDate);
  }

  return alerts.slice(-100); // Return last 100 matching
}

function acknowledgeAlert(alertId) {
  const alert = trackingData.alerts.find(a => a.id === alertId);
  if (alert) {
    alert.acknowledged = true;
    alert.acknowledgedAt = new Date().toISOString();
    return true;
  }
  return false;
}

// ================== IP BLOCKING ==================

function isIPBlocked(ipAddress) {
  return trackingData.blockedIPs.has(ipAddress);
}

function unblockIP(ipAddress) {
  trackingData.blockedIPs.delete(ipAddress);
  trackingData.loginFailuresByIP.delete(ipAddress);
}

function getBlockedIPs() {
  return Array.from(trackingData.blockedIPs);
}

// ================== JWT SECURITY EVENTS ==================

function logJWTExpired(userId, ipAddress) {
  winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.JWT_EXPIRED, {
    userId, ipAddress, details: { reason: 'Token expired' }
  });
}

function logJWTInvalid(ipAddress, reason) {
  winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.JWT_INVALID_SIGNATURE, {
    ipAddress, details: { reason }
  });

  // Track as potential attack
  trackLoginFailure(ipAddress, null);
}

function logUnauthorizedAccess(userId, role, resource, ipAddress) {
  winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.UNAUTHORIZED_ACCESS_ATTEMPT, {
    userId, role, ipAddress, details: { resource }
  });
  createAlert('UNAUTHORIZED_ACCESS', 'warning', { userId, role, resource, ipAddress });
}

// ================== METRICS FOR PROMETHEUS ==================

function getSecurityMetrics() {
  return {
    blockedIPCount: trackingData.blockedIPs.size,
    activeAlerts: trackingData.alerts.filter(a => !a.acknowledged).length,
    criticalAlerts: trackingData.alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length,
    loginFailuresLast15min: Array.from(trackingData.loginFailuresByIP.values())
      .reduce((sum, entries) => sum + getRecentEntries(entries, THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW).length, 0),
    thresholds: THRESHOLDS
  };
}

function getPrometheusSecurityMetrics() {
  const metrics = getSecurityMetrics();
  const lines = [];

  lines.push('# HELP healthcare_blocked_ips_total Currently blocked IP addresses');
  lines.push('# TYPE healthcare_blocked_ips_total gauge');
  lines.push(`healthcare_blocked_ips_total ${metrics.blockedIPCount}`);

  lines.push('# HELP healthcare_security_alerts_active Active unacknowledged security alerts');
  lines.push('# TYPE healthcare_security_alerts_active gauge');
  lines.push(`healthcare_security_alerts_active ${metrics.activeAlerts}`);

  lines.push('# HELP healthcare_security_alerts_critical Critical security alerts');
  lines.push('# TYPE healthcare_security_alerts_critical gauge');
  lines.push(`healthcare_security_alerts_critical ${metrics.criticalAlerts}`);

  lines.push('# HELP healthcare_login_failures_15min Login failures in last 15 minutes');
  lines.push('# TYPE healthcare_login_failures_15min gauge');
  lines.push(`healthcare_login_failures_15min ${metrics.loginFailuresLast15min}`);

  return lines.join('\n');
}

module.exports = {
  // Tracking functions
  trackLoginFailure, trackDecryptRequest, trackPatientAccess, trackAccountAccess,

  // Alert functions
  createAlert, getAlerts, acknowledgeAlert,

  // IP blocking
  isIPBlocked, unblockIP, getBlockedIPs,

  // JWT security
  logJWTExpired, logJWTInvalid, logUnauthorizedAccess,

  // Metrics
  getSecurityMetrics, getPrometheusSecurityMetrics,

  // Phase 2 Integration
  sendTelemetryToPhase2, sendAlertToResponseController, PHASE2_CONFIG,

  // Config
  THRESHOLDS, trackingData
};

