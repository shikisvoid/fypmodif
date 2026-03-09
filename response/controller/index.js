const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 4100;

const LOG_DIR = '/logs';
const ALERT_LOG = path.join(LOG_DIR, 'security-alerts.log');
const ROLE_VIOLATIONS_LOG = path.join(LOG_DIR, 'role-violations.log');
const ISOLATIONS_FILE = path.join(LOG_DIR, 'isolations.json');

// IAM Server configuration for Phase 2 integration
const IAM_CONFIG = {
  HOST: process.env.IAM_HOST || '172.21.0.40',
  PORT: process.env.IAM_PORT || 4000
};

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

function writeLog(file, message) {
  const timestamp = new Date().toISOString();
  fs.appendFileSync(file, `[${timestamp}] ${message}\n`);
}

/**
 * Call IAM server to revoke user tokens
 */
function revokeUserTokens(email, ipAddress, reason) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ email, ipAddress, reason });
    const options = {
      hostname: IAM_CONFIG.HOST,
      port: IAM_CONFIG.PORT,
      path: '/api/security/revoke-user',
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
          console.log(`[IAM] Token revocation response:`, response);
          writeLog(ALERT_LOG, `IAM_REVOKE: email=${email || 'N/A'} ip=${ipAddress || 'N/A'} result=${JSON.stringify(response)}`);
          resolve(response);
        } catch (e) {
          resolve({ success: false, error: 'Parse error' });
        }
      });
    });

    req.on('error', (err) => {
      console.warn(`[IAM] Token revocation failed: ${err.message}`);
      writeLog(ALERT_LOG, `IAM_REVOKE_FAILED: ${err.message}`);
      resolve({ success: false, error: err.message });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'timeout' });
    });

    req.write(postData);
    req.end();
  });
}

/**
 * Call IAM server to block an IP
 */
function blockIPAddress(ipAddress, reason) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ ipAddress, reason, duration: '24h' });
    const options = {
      hostname: IAM_CONFIG.HOST,
      port: IAM_CONFIG.PORT,
      path: '/api/security/block-ip',
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
          console.log(`[IAM] IP block response:`, response);
          writeLog(ALERT_LOG, `IAM_BLOCK_IP: ip=${ipAddress} result=${JSON.stringify(response)}`);
          resolve(response);
        } catch (e) {
          resolve({ success: false, error: 'Parse error' });
        }
      });
    });

    req.on('error', (err) => {
      console.warn(`[IAM] IP block failed: ${err.message}`);
      resolve({ success: false, error: err.message });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'timeout' });
    });

    req.write(postData);
    req.end();
  });
}

app.use(bodyParser.json());

// Basic alert receiver
app.post('/alert', async (req, res) => {
  try {
    const alert = req.body;
    const message = `ALERT_RECEIVED: severity=${alert.severity} event=${alert.event} host=${alert.hostId} details=${JSON.stringify(alert.details || {})}`;
    writeLog(ALERT_LOG, message);
    console.log('▶ Received alert:', message);

    const details = alert.details || {};
    const userEmail = details.userEmail || details.email || null;
    const userRole = details.userRole || null;

    // ===== ROLE-BASED ACCESS VIOLATION HANDLING =====
    // These are HIGH severity — revoke the user's tokens immediately
    if (alert.event === 'ROLE_ACCESS_VIOLATION' && userEmail) {
      writeLog(ROLE_VIOLATIONS_LOG, `VIOLATION: role=${userRole} email=${userEmail} method=${details.method} path=${details.path} host=${alert.hostId}`);
      console.log(`[Phase2] ⚠️ Role violation: ${userEmail} (${userRole}) -> ${details.method} ${details.path}`);

      const iamActions = [];
      console.log(`[Phase2] 🔐 Revoking tokens for violating user: ${userEmail}`);
      const revokeResult = await revokeUserTokens(userEmail, null, `ROLE_ACCESS_VIOLATION: ${userRole} -> ${details.path}`);
      iamActions.push({ type: 'revoke_user', email: userEmail, result: revokeResult });

      // Record the action
      let isolations = [];
      try { isolations = JSON.parse(fs.readFileSync(ISOLATIONS_FILE, 'utf8') || '[]'); } catch {}
      isolations.push({
        hostId: alert.hostId || 'unknown',
        action: 'revoke_tokens',
        reason: alert.event,
        userEmail,
        userRole,
        path: details.path,
        alert,
        ts: new Date().toISOString(),
        iamActions
      });
      fs.writeFileSync(ISOLATIONS_FILE, JSON.stringify(isolations, null, 2));
      writeLog(ALERT_LOG, `ACTION_TAKEN: revoke_tokens user=${userEmail} role=${userRole} path=${details.path}`);
      return res.json({ ok: true, action: 'revoke_tokens', userEmail, iamActions: iamActions.length });
    }

    // ===== ML ANOMALY HANDLING (Phase 2: Behavioral ML Detection) =====
    const ML_EVENTS = ['ML_ANOMALY', 'ML_RULE_CORRELATED'];
    if (ML_EVENTS.includes(alert.event)) {
      const mlClassification = details.classification || details.ml_classification || 'unknown';
      const mlScore = details.anomaly_score || details.ml_score || 0;
      const mlConfidence = details.confidence || details.ml_confidence || 0;
      const detectionType = details.detection_type || 'ml';

      writeLog(ALERT_LOG, `ML_DETECTION: event=${alert.event} class=${mlClassification} score=${mlScore} confidence=${mlConfidence} role=${userRole} email=${userEmail} host=${alert.hostId} type=${detectionType}`);
      console.log(`[Phase2] 🧠 ML Detection: ${alert.event} — ${mlClassification} (score=${mlScore}, confidence=${mlConfidence}) from ${userEmail || alert.hostId} (${userRole || 'unknown'})`);

      // ML_RULE_CORRELATED → both ML and rules detected, escalate to CRITICAL
      if (alert.event === 'ML_RULE_CORRELATED') {
        console.log(`[Phase2] ⚡ HYBRID ALERT: ML + Rule correlated detection — escalating response`);
        writeLog(ALERT_LOG, `HYBRID_ESCALATION: ML+Rule correlated for ${userEmail || alert.hostId}`);
        // Falls through to CRITICAL handler below
      }

      // ML-only Suspicious → log alert only (no automated action)
      if (alert.event === 'ML_ANOMALY' && mlClassification === 'Suspicious' && alert.severity !== 'CRITICAL') {
        writeLog(ALERT_LOG, `ML_SUSPICIOUS_LOGGED: score=${mlScore} user=${userEmail || 'N/A'} host=${alert.hostId}`);
        console.log(`[Phase2] 📋 ML Suspicious logged (no automated action): ${userEmail || alert.hostId}`);
        return res.json({ ok: true, action: 'log_only', classification: mlClassification, score: mlScore });
      }
      // ML-only Malicious or ML_RULE_CORRELATED continue to CRITICAL/HIGH handlers
    }

    // ===== DATABASE SECURITY ALERT HANDLING =====
    const DB_EVENTS = ['DB_MASS_DELETE', 'DB_MASS_DELETE_STATS', 'DB_UNAUTHORIZED_TABLE_ACCESS',
                       'DB_BULK_DATA_READ', 'DB_SUDDEN_ROW_DROP', 'DB_LONG_RUNNING_QUERY', 'DB_SCHEMA_CHANGE'];
    if (DB_EVENTS.includes(alert.event)) {
      writeLog(ROLE_VIOLATIONS_LOG, `DB_ALERT: event=${alert.event} role=${userRole} email=${userEmail} table=${details.table || 'N/A'} host=${alert.hostId}`);
      console.log(`[Phase2] 🗄️ Database alert: ${alert.event} from ${userEmail || alert.hostId} (${userRole || 'unknown'})`);
      // DB alerts continue to CRITICAL/HIGH handlers below for automated response
    }

    // ===== CRITICAL ALERT HANDLING (exfiltration, ransomware, DB mass delete, schema change, etc.) =====
    if (alert.severity === 'CRITICAL') {
      let isolations = [];
      try { isolations = JSON.parse(fs.readFileSync(ISOLATIONS_FILE, 'utf8') || '[]'); } catch {}
      const action = {
        hostId: alert.hostId || 'unknown',
        action: 'isolate',
        reason: alert.event || 'alert',
        userEmail,
        userRole,
        alert,
        ts: new Date().toISOString(),
        iamActions: []
      };

      // Revoke tokens for the user associated with this alert
      if (userEmail) {
        console.log(`[Phase2] 🔐 Revoking tokens for user: ${userEmail} (role=${userRole})`);
        const revokeResult = await revokeUserTokens(userEmail, null, alert.event);
        action.iamActions.push({ type: 'revoke_user', email: userEmail, result: revokeResult });
      }

      // If alert contains IP address (brute force), block the IP
      if (details.ipAddress) {
        console.log(`[Phase2] 🚫 Blocking IP: ${details.ipAddress}`);
        const blockResult = await blockIPAddress(details.ipAddress, alert.event);
        action.iamActions.push({ type: 'block_ip', ip: details.ipAddress, result: blockResult });

        if (details.targetedEmails && Array.isArray(details.targetedEmails)) {
          for (const email of details.targetedEmails) {
            const revokeResult = await revokeUserTokens(email, details.ipAddress, `${alert.event}_from_blocked_ip`);
            action.iamActions.push({ type: 'revoke_user', email, result: revokeResult });
          }
        }
      }

      isolations.push(action);
      fs.writeFileSync(ISOLATIONS_FILE, JSON.stringify(isolations, null, 2));
      writeLog(ALERT_LOG, `ACTION_TAKEN: isolate host=${action.hostId} user=${userEmail || 'N/A'} role=${userRole || 'N/A'} iamActions=${action.iamActions.length}`);
      console.log(`✔ Action taken: isolate host=${action.hostId}, user=${userEmail || 'N/A'}, IAM actions: ${action.iamActions.length}`);
      return res.json({ ok: true, action: 'isolate', hostId: action.hostId, userEmail, iamActions: action.iamActions.length });
    }

    // ===== HIGH SEVERITY (brute force, etc.) =====
    if (alert.severity === 'HIGH') {
      const iamActions = [];
      if (userEmail) {
        console.log(`[Phase2] 🔐 Revoking tokens for HIGH alert user: ${userEmail}`);
        const revokeResult = await revokeUserTokens(userEmail, null, alert.event);
        iamActions.push({ type: 'revoke_user', email: userEmail, result: revokeResult });
      }
      if (details.ipAddress) {
        console.log(`[Phase2] 🚫 Blocking IP for HIGH alert: ${details.ipAddress}`);
        const blockResult = await blockIPAddress(details.ipAddress, alert.event);
        iamActions.push({ type: 'block_ip', ip: details.ipAddress, result: blockResult });
      }

      let isolations = [];
      try { isolations = JSON.parse(fs.readFileSync(ISOLATIONS_FILE, 'utf8') || '[]'); } catch {}
      isolations.push({
        hostId: alert.hostId || 'unknown',
        action: 'restrict',
        reason: alert.event,
        userEmail,
        userRole,
        alert,
        ts: new Date().toISOString(),
        iamActions
      });
      fs.writeFileSync(ISOLATIONS_FILE, JSON.stringify(isolations, null, 2));
      writeLog(ALERT_LOG, `ACTION_TAKEN: restrict host=${alert.hostId} user=${userEmail || 'N/A'} iamActions=${iamActions.length}`);
      return res.json({ ok: true, action: 'restrict', hostId: alert.hostId, userEmail, iamActions: iamActions.length });
    }

    // For non-critical/non-high alerts, just acknowledge
    res.json({ ok: true, received: true });

  } catch (err) {
    console.error('Error handling alert:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Revert action endpoint
app.post('/action/revert', (req, res) => {
  const { hostId } = req.body || {};
  try {
    let isolations = [];
    try { isolations = JSON.parse(fs.readFileSync(ISOLATIONS_FILE, 'utf8') || '[]'); } catch {}
    const reverts = isolations.filter(i => i.hostId === hostId);

    // Mark revert entry
    const revertEntry = {
      hostId: hostId || 'unknown',
      action: 'revert_isolation',
      ts: new Date().toISOString(),
      reverts: reverts
    };
    isolations.push(revertEntry);
    fs.writeFileSync(ISOLATIONS_FILE, JSON.stringify(isolations, null, 2));
    writeLog(ALERT_LOG, `ACTION_REVERT: host=${hostId}`);
    res.json({ ok: true, reverted: true, hostId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/isolations', (req, res) => {
  try {
    let isolations = [];
    try { isolations = JSON.parse(fs.readFileSync(ISOLATIONS_FILE, 'utf8') || '[]'); } catch {}
    res.json(isolations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => res.send('Response Controller is running'));

app.listen(PORT, () => {
  console.log(`Response Controller running on http://localhost:${PORT}`);
  writeLog(ALERT_LOG, `Controller started on port ${PORT}`);
});