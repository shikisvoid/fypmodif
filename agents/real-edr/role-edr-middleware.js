/**
 * Role-Aware EDR Middleware for Express Servers
 * Intercepts all authenticated requests and sends role-tagged telemetry
 * to the central Phase 2 telemetry collector.
 *
 * Usage:
 *   const { createEdrMiddleware } = require('./role-edr-middleware');
 *   app.use(createEdrMiddleware({ hostId: 'hospital-iam', target: '...' }));
 */

const http = require('http');

// Default config
const DEFAULTS = {
  hostId: 'unknown-host',
  target: 'http://172.21.0.100:9090/ingest/telemetry',
  batchIntervalMs: 2000,
  maxBatchSize: 50
};

// Role-based access policy: what each role is ALLOWED to access
const ROLE_ACCESS_POLICY = {
  admin:          { allowed: ['/api/patients', '/api/appointments', '/api/billing', '/api/labs', '/api/pharmacy', '/api/admin', '/api/settings', '/api/me', '/api/notifications', '/api/doctor', '/api/nurse', '/api/receptionist', '/api/accountant'] },
  doctor:         { allowed: ['/api/patients', '/api/appointments', '/api/doctor', '/api/me', '/api/notifications', '/api/labs', '/api/records'] },
  nurse:          { allowed: ['/api/patients', '/api/appointments', '/api/nurse', '/api/me', '/api/notifications', '/api/labs'] },
  receptionist:   { allowed: ['/api/patients', '/api/appointments', '/api/receptionist', '/api/me', '/api/notifications', '/api/billing'] },
  lab_technician: { allowed: ['/api/patients', '/api/labs', '/api/me', '/api/notifications', '/api/records'] },
  pharmacist:     { allowed: ['/api/patients', '/api/pharmacy', '/api/me', '/api/notifications'] },
  accountant:     { allowed: ['/api/billing', '/api/patients', '/api/accountant', '/api/me', '/api/notifications'] },
  patient:        { allowed: ['/api/me', '/api/records', '/api/billing', '/api/notifications'] }
};

// Sensitive endpoints that always trigger telemetry
const SENSITIVE_ENDPOINTS = [
  '/api/admin', '/api/settings', '/api/security',
  '/api/billing', '/api/patients', '/api/records'
];

function sendTelemetry(target, payload) {
  try {
    const data = JSON.stringify(payload);
    const url = new URL(target);
    const options = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: 3000
    };
    const req = http.request(options, () => {});
    req.on('error', () => {});
    req.on('timeout', () => req.destroy());
    req.write(data);
    req.end();
  } catch (e) { /* silently fail */ }
}

function checkRoleViolation(role, path) {
  if (!role || !ROLE_ACCESS_POLICY[role]) return null;
  const policy = ROLE_ACCESS_POLICY[role];
  // Check if the path matches any allowed prefix
  const isAllowed = policy.allowed.some(prefix => path.startsWith(prefix));
  if (!isAllowed && path.startsWith('/api/') && !path.startsWith('/api/login') &&
      !path.startsWith('/api/mfa') && !path.startsWith('/api/token') &&
      !path.startsWith('/api/logout') && !path.startsWith('/api/health')) {
    return { violation: true, role, path, allowed: policy.allowed };
  }
  return null;
}

function createEdrMiddleware(config = {}) {
  const hostId = config.hostId || process.env.EDR_HOST_ID || DEFAULTS.hostId;
  const target = config.target || process.env.EDR_TARGET || DEFAULTS.target;
  const batchIntervalMs = config.batchIntervalMs || DEFAULTS.batchIntervalMs;
  const maxBatchSize = config.maxBatchSize || DEFAULTS.maxBatchSize;

  let telemetryBatch = [];

  // Flush batch periodically
  setInterval(() => {
    if (telemetryBatch.length === 0) return;
    const batch = telemetryBatch.splice(0);
    const payload = {
      hostId,
      ts: new Date().toISOString(),
      source: 'edr-role-middleware',
      eventType: 'ROLE_ACTIVITY_BATCH',
      roleActivity: batch,
      batchSize: batch.length
    };
    sendTelemetry(target, payload);
  }, batchIntervalMs);

  return function edrMiddleware(req, res, next) {
    const startTime = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const userEmail = req.userEmail || req.user?.email || 'anonymous';
      const userRole = req.userRole || req.user?.role || 'unknown';
      const apiPath = req.path || req.url;
      const method = req.method;

      const entry = {
        ts: new Date().toISOString(),
        userEmail,
        userRole,
        method,
        path: apiPath,
        statusCode: res.statusCode,
        durationMs: duration,
        ip: req.ip || req.connection?.remoteAddress || 'unknown'
      };

      // Check for role-based access violations
      const violation = checkRoleViolation(userRole, apiPath);
      if (violation) {
        entry.violation = true;
        entry.violationType = 'ROLE_ACCESS_VIOLATION';
        entry.allowedPaths = violation.allowed;
        // Send violation immediately (don't batch)
        const alertPayload = {
          hostId,
          ts: entry.ts,
          source: 'edr-role-middleware',
          eventType: 'ROLE_ACCESS_VIOLATION',
          severity: 'HIGH',
          security: entry
        };
        sendTelemetry(target, alertPayload);
        console.log(`[EDR] ⚠️  ROLE VIOLATION: ${userRole} (${userEmail}) accessed ${apiPath}`);
      }

      // Check for sensitive endpoint access
      const isSensitive = SENSITIVE_ENDPOINTS.some(ep => apiPath.startsWith(ep));
      if (isSensitive) {
        entry.sensitiveAccess = true;
      }

      // Add to batch
      telemetryBatch.push(entry);
      if (telemetryBatch.length >= maxBatchSize) {
        const batch = telemetryBatch.splice(0);
        const payload = {
          hostId, ts: new Date().toISOString(), source: 'edr-role-middleware',
          eventType: 'ROLE_ACTIVITY_BATCH', roleActivity: batch, batchSize: batch.length
        };
        sendTelemetry(target, payload);
      }
    });

    next();
  };
}

module.exports = { createEdrMiddleware, checkRoleViolation, ROLE_ACCESS_POLICY, sendTelemetry };

