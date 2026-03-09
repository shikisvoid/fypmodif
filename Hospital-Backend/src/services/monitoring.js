/**
 * Monitoring Service for Healthcare System
 * 
 * Provides Prometheus-compatible metrics and health monitoring
 * for all system components including:
 * - API performance metrics
 * - Security metrics (login failures, MFA, encryption)
 * - Dashboard health monitoring
 * - File upload/download tracking
 */

const logger = require('./logger');

// Prometheus-style metrics storage
const metrics = {
  // Counters
  http_requests_total: {},
  http_request_errors_total: {},
  login_attempts_total: { success: 0, failure: 0 },
  mfa_verifications_total: { success: 0, failure: 0 },
  encryption_operations_total: { encrypt: 0, decrypt: 0, denied: 0 },
  file_operations_total: { upload: 0, download: 0, error: 0 },
  
  // Gauges
  active_sessions: 0,
  database_connections: 0,
  
  // Histograms (simplified as arrays)
  http_request_duration_seconds: [],
  encryption_duration_seconds: [],
  
  // Dashboard health
  dashboard_refresh_failures: {},
  dashboard_data_freshness: {},
  
  // System info
  start_time: Date.now(),
  last_updated: Date.now()
};

/**
 * Record HTTP request metrics
 */
function recordHttpRequest(method, path, statusCode, durationMs) {
  const key = `${method}:${path}`;
  metrics.http_requests_total[key] = (metrics.http_requests_total[key] || 0) + 1;
  
  if (statusCode >= 400) {
    metrics.http_request_errors_total[key] = (metrics.http_request_errors_total[key] || 0) + 1;
  }
  
  metrics.http_request_duration_seconds.push({
    method, path, statusCode, duration: durationMs / 1000, timestamp: Date.now()
  });
  
  // Keep only last 1000 entries
  if (metrics.http_request_duration_seconds.length > 1000) {
    metrics.http_request_duration_seconds = metrics.http_request_duration_seconds.slice(-1000);
  }
  
  metrics.last_updated = Date.now();
}

/**
 * Record login attempt
 */
function recordLoginAttempt(success, userEmail, ipAddress) {
  if (success) {
    metrics.login_attempts_total.success++;
    metrics.active_sessions++;
  } else {
    metrics.login_attempts_total.failure++;
  }
  metrics.last_updated = Date.now();
}

/**
 * Record logout
 */
function recordLogout() {
  if (metrics.active_sessions > 0) metrics.active_sessions--;
  metrics.last_updated = Date.now();
}

/**
 * Record MFA verification
 */
function recordMfaVerification(success, userId) {
  if (success) {
    metrics.mfa_verifications_total.success++;
  } else {
    metrics.mfa_verifications_total.failure++;
  }
  metrics.last_updated = Date.now();
}

/**
 * Record encryption operation
 */
function recordEncryptionOp(operation, durationMs) {
  metrics.encryption_operations_total[operation] = 
    (metrics.encryption_operations_total[operation] || 0) + 1;
  
  if (durationMs) {
    metrics.encryption_duration_seconds.push({
      operation, duration: durationMs / 1000, timestamp: Date.now()
    });
    if (metrics.encryption_duration_seconds.length > 500) {
      metrics.encryption_duration_seconds = metrics.encryption_duration_seconds.slice(-500);
    }
  }
  metrics.last_updated = Date.now();
}

/**
 * Record file operation
 */
function recordFileOperation(operation, success, fileSize, error = null) {
  if (success) {
    metrics.file_operations_total[operation] = 
      (metrics.file_operations_total[operation] || 0) + 1;
  } else {
    metrics.file_operations_total.error++;
    logger.log({
      service: logger.SERVICE.SYSTEM,
      eventType: 'FILE_OPERATION_ERROR',
      severity: logger.SEVERITY.ERROR,
      details: { operation, error: error?.message, fileSize }
    });
  }
  metrics.last_updated = Date.now();
}

/**
 * Record dashboard health
 */
function recordDashboardHealth(dashboardName, success, dataAge = null) {
  if (!success) {
    metrics.dashboard_refresh_failures[dashboardName] = 
      (metrics.dashboard_refresh_failures[dashboardName] || 0) + 1;
  }
  if (dataAge !== null) {
    metrics.dashboard_data_freshness[dashboardName] = dataAge;
  }
  metrics.last_updated = Date.now();
}

/**
 * Get Prometheus-formatted metrics
 */
function getPrometheusMetrics() {
  const lines = [];
  const uptime = (Date.now() - metrics.start_time) / 1000;
  
  lines.push('# HELP healthcare_uptime_seconds System uptime in seconds');
  lines.push('# TYPE healthcare_uptime_seconds gauge');
  lines.push(`healthcare_uptime_seconds ${uptime}`);
  
  lines.push('# HELP healthcare_active_sessions Current active sessions');
  lines.push('# TYPE healthcare_active_sessions gauge');
  lines.push(`healthcare_active_sessions ${metrics.active_sessions}`);
  
  lines.push('# HELP healthcare_login_attempts_total Total login attempts');
  lines.push('# TYPE healthcare_login_attempts_total counter');
  lines.push(`healthcare_login_attempts_total{result="success"} ${metrics.login_attempts_total.success}`);
  lines.push(`healthcare_login_attempts_total{result="failure"} ${metrics.login_attempts_total.failure}`);
  
  lines.push('# HELP healthcare_mfa_verifications_total Total MFA verifications');
  lines.push('# TYPE healthcare_mfa_verifications_total counter');
  lines.push(`healthcare_mfa_verifications_total{result="success"} ${metrics.mfa_verifications_total.success}`);
  lines.push(`healthcare_mfa_verifications_total{result="failure"} ${metrics.mfa_verifications_total.failure}`);
  
  lines.push('# HELP healthcare_encryption_ops_total Total encryption operations');
  lines.push('# TYPE healthcare_encryption_ops_total counter');
  for (const [op, count] of Object.entries(metrics.encryption_operations_total)) {
    lines.push(`healthcare_encryption_ops_total{operation="${op}"} ${count}`);
  }
  
  lines.push('# HELP healthcare_file_ops_total Total file operations');
  lines.push('# TYPE healthcare_file_ops_total counter');
  for (const [op, count] of Object.entries(metrics.file_operations_total)) {
    lines.push(`healthcare_file_ops_total{operation="${op}"} ${count}`);
  }
  
  return lines.join('\n');
}

/**
 * Get JSON metrics for dashboard
 */
function getJsonMetrics() {
  return {
    uptime: (Date.now() - metrics.start_time) / 1000,
    activeSessions: metrics.active_sessions,
    loginAttempts: metrics.login_attempts_total,
    mfaVerifications: metrics.mfa_verifications_total,
    encryptionOps: metrics.encryption_operations_total,
    fileOps: metrics.file_operations_total,
    dashboardHealth: {
      refreshFailures: metrics.dashboard_refresh_failures,
      dataFreshness: metrics.dashboard_data_freshness
    },
    lastUpdated: new Date(metrics.last_updated).toISOString()
  };
}

module.exports = {
  recordHttpRequest, recordLoginAttempt, recordLogout,
  recordMfaVerification, recordEncryptionOp, recordFileOperation,
  recordDashboardHealth, getPrometheusMetrics, getJsonMetrics, metrics
};

