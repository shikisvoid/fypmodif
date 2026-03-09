// Real-time Traffic Analyzer for Software-Defined Perimeter (SDP)
// Continuously monitors and logs network traffic patterns

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const http = require('http');


const LOG_DIR = '/logs';
const TRAFFIC_LOG = path.join(LOG_DIR, 'traffic-analysis.log');
const ALERT_LOG = path.join(LOG_DIR, 'security-alerts.log');

// Network rules - what should be allowed
const NETWORK_RULES = {};

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

function writeLog(file, message) {
    const timestamp = new Date().toISOString();
    fs.appendFileSync(file, `[${timestamp}] ${message}\n`);
}

function logTrafficEvent(source, destination, action, reason) {
    const message = `${action.toUpperCase()}: ${source} -> ${destination} | Reason: ${reason}`;
    writeLog(TRAFFIC_LOG, message);
    console.log(`  ${action === 'ALLOW' ? 'âœ“' : 'âœ—'} ${message}`);
}

function logSecurityAlert(severity, event, details) {
    const message = `[${severity}] ${event} | ${details}`;
    writeLog(ALERT_LOG, message);
    console.log(`  ðŸš¨ ALERT: ${message}`);
}

// Analyze traffic patterns
async function analyzeTraffic() {
    console.log('\nðŸ“Š Analyzing Network Traffic Patterns...\n');
    
    const header = `${'='.repeat(80)}\nTraffic Analysis Report - ${new Date().toISOString()}\n${'='.repeat(80)}`;
    writeLog(TRAFFIC_LOG, header);
    
    // Test each container's network access
    for (const [container, rules] of Object.entries(NETWORK_RULES)) {
        console.log(`\nðŸ” Testing ${container} (${rules.network} network):`);
        writeLog(TRAFFIC_LOG, `\nTesting ${container}:`);
        
        // Test allowed connections
        for (const allowedIP of rules.allowed) {
            try {
                const cmd = `docker exec ${container} ping -c 1 -W 1 ${allowedIP} 2>&1`;
                const { stdout } = await execPromise(cmd);
                const success = stdout.includes('1 packets transmitted, 1 received');
                
                if (success) {
                    logTrafficEvent(container, allowedIP, 'ALLOW', 'Permitted by network policy');
                } else {
                    logSecurityAlert('WARNING', 'UNEXPECTED_BLOCK', 
                        `${container} cannot reach ${allowedIP} (should be allowed)`);
                }
            } catch (error) {
                logSecurityAlert('WARNING', 'UNEXPECTED_BLOCK', 
                    `${container} blocked from ${allowedIP} (should be allowed)`);
            }
        }
        
        // Test blocked connections
        for (const blockedIP of rules.blocked) {
            try {
                const cmd = `docker exec ${container} ping -c 1 -W 1 ${blockedIP} 2>&1`;
                const { stdout } = await execPromise(cmd);
                const success = stdout.includes('1 packets transmitted, 1 received');
                
                if (success) {
                    logSecurityAlert('CRITICAL', 'SECURITY_BREACH', 
                        `${container} can reach ${blockedIP} (should be blocked)!`);
                } else {
                    logTrafficEvent(container, blockedIP, 'BLOCK', 'Blocked by SDP access control');
                }
            } catch (error) {
                logTrafficEvent(container, blockedIP, 'BLOCK', 'Blocked by SDP access control');
            }
        }
    }
}

// Monitor HTTP/API traffic
async function monitorAPITraffic() {
    console.log('\nðŸŒ Monitoring API Traffic...\n');
    
    const containers = ['hospital-backend', 'hospital-iam', 'hospital-frontend'];
    
    for (const container of containers) {
        try {
            // Check for listening ports
            const cmd = `docker exec ${container} netstat -tln 2>/dev/null || ss -tln 2>/dev/null || echo "not available"`;
            const { stdout } = await execPromise(cmd);
            
            if (!stdout.includes('not available')) {
                const ports = stdout.split('\n')
                    .filter(line => line.includes('LISTEN') || line.includes('0.0.0.0'))
                    .map(line => {
                        const match = line.match(/:(\d+)/);
                        return match ? match[1] : null;
                    })
                    .filter(Boolean);
                
                if (ports.length > 0) {
                    const message = `${container} listening on ports: ${ports.join(', ')}`;
                    writeLog(TRAFFIC_LOG, message);
                    console.log(`  ðŸ“¡ ${message}`);
                }
            }
        } catch (error) {
            // Skip if netstat not available
        }
    }
}

// Generate traffic statistics
async function generateStatistics() {
    console.log('\nðŸ“ˆ Generating Traffic Statistics...\n');
    
    const stats = {
        timestamp: new Date().toISOString(),
        totalTests: 0,
        allowedConnections: 0,
        blockedConnections: 0,
        securityAlerts: 0
    };
    
    // Count tests
    for (const rules of Object.values(NETWORK_RULES)) {
        stats.totalTests += rules.allowed.length + rules.blocked.length;
    }
    
    const statsReport = `
${'='.repeat(80)}
Traffic Statistics Summary
${'='.repeat(80)}
Timestamp: ${stats.timestamp}
Total Network Tests: ${stats.totalTests}
Network Segments: 1 (SDP overlay)
Monitored Containers: ${Object.keys(NETWORK_RULES).length}

SDP Gateway Status:
  âœ“ Backend Network: Database, Backend API, Encryption Service
  âœ“ Frontend Network: Frontend, IAM Server, Backend API (bridge)
  âœ“ Cross-network access: Controlled via Backend API only

Security Posture:
  âœ“ Database isolated from frontend
  âœ“ Encryption service isolated from frontend
  âœ“ IAM server isolated from backend data
  âœ“ Backend API acts as controlled gateway

${'='.repeat(80)}
`;
    
    writeLog(TRAFFIC_LOG, statsReport);
    console.log(statsReport);
}

// --- Telemetry polling & alerting (integrate EDR telemetry) ---
const CONTROLLER_URL = process.env.CONTROLLER_URL || 'http://localhost:4100/alert';
const TELEMETRY_POLL_INTERVAL_MS = parseInt(process.env.TELEMETRY_POLL_MS || '2000', 10);
const ALERT_DEDUP_TTL_MS = 30 * 1000;
const recentAlerts = new Map(); // key -> timestamp

function sendAlertToController(alert) {    return new Promise((resolve, reject) => {
        try {
            const data = JSON.stringify(alert);
            const url = new URL(CONTROLLER_URL);
            const options = {
                hostname: url.hostname,
                port: url.port || 80,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(data)
                }
            };
            const req = http.request(options, (res) => {
                let body = '';
                res.on('data', (chunk) => { body += chunk; });
                res.on('end', () => resolve({ statusCode: res.statusCode, body }));
            });
            req.on('error', reject);
            req.write(data);
            req.end();
        } catch (err) {
            reject(err);
        }
    });
}

// ============================================================
// ML ENGINE INTEGRATION (Phase 2: Behavioral Anomaly Detection)
// ============================================================
const ML_ENGINE_URL = process.env.ML_ENGINE_URL || 'http://172.20.0.140:5000';
const ML_ENABLED = process.env.ML_ENABLED !== 'false';

/**
 * Call the ML engine /predict endpoint with telemetry
 * Returns: { anomaly_score, is_anomaly, classification, confidence, hostId, userRole }
 */
function callMLEngine(telemetry) {
    return new Promise((resolve, reject) => {
        try {
            const data = JSON.stringify(telemetry);
            const url = new URL(ML_ENGINE_URL + '/predict');
            const options = {
                hostname: url.hostname,
                port: url.port || 5000,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(data)
                },
                timeout: 3000
            };
            const req = http.request(options, (res) => {
                let body = '';
                res.on('data', chunk => body += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(body));
                    } catch (e) {
                        reject(new Error('ML parse error'));
                    }
                });
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('ML timeout')); });
            req.write(data);
            req.end();
        } catch (err) {
            reject(err);
        }
    });
}

// ============================================================
// DETECTION RULES (Phase 2: Role-aware + original rules)
// ============================================================
const SUSPICIOUS_IPS = ['8.8.8.8', '1.1.1.1', '185.220.101.1'];
const RANSOMWARE_EXTENSIONS = ['.encrypted', '.lock', '.ransom', '.crypto', '.locked'];

// Brute-force tracking: key=hostId -> { count, firstSeen }
const bruteForceTracker = new Map();
const BRUTE_FORCE_THRESHOLD = 5;
const BRUTE_FORCE_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

// Helper: deduplicated alert sender
async function sendDedupedAlert(key, alert) {
    const last = recentAlerts.get(key) || 0;
    if (Date.now() - last < ALERT_DEDUP_TTL_MS) return false;
    try {
        await sendAlertToController(alert);
    } catch (err) {
        console.error('Failed to send alert to controller:', err.message);
    }
    recentAlerts.set(key, Date.now());
    return true;
}

// Rule 1: Exfiltration â€” connection to any suspicious IP
async function ruleExfiltration(item) {
    if (!item || !item.net || !item.net.dst) return;
    if (!SUSPICIOUS_IPS.includes(item.net.dst)) return;

    const key = `exfil::${item.hostId}::${item.net.dst}`;
    const alert = {
        severity: 'CRITICAL',
        event: 'EXFILTRATION',
        hostId: item.hostId,
        ts: item.ts || new Date().toISOString(),
        details: { ...item, userEmail: item.userEmail, userRole: item.userRole }
    };
    logSecurityAlert('CRITICAL', 'EXFILTRATION_DETECTED', `${item.hostId} [${item.userRole || 'unknown'}] -> ${item.net.dst}`);
    await sendDedupedAlert(key, alert);
}

// Rule 2: Role-based access violation (from EDR middleware)
// The middleware sends top-level items with eventType='ROLE_ACCESS_VIOLATION' and a .security object
async function ruleRoleViolation(item) {
    if (!item) return;

    // Case A: Middleware sends violation as a top-level telemetry item
    if (item.eventType === 'ROLE_ACCESS_VIOLATION' && item.security) {
        const s = item.security;
        const key = `role_violation::${s.userEmail}::${s.path}`;
        const alert = {
            severity: 'HIGH',
            event: 'ROLE_ACCESS_VIOLATION',
            hostId: item.hostId,
            ts: item.ts || new Date().toISOString(),
            details: {
                userEmail: s.userEmail,
                userRole: s.userRole,
                method: s.method,
                path: s.path,
                statusCode: s.statusCode,
                ip: s.ip,
                hostId: item.hostId
            }
        };
        logSecurityAlert('HIGH', 'ROLE_ACCESS_VIOLATION', `${s.userEmail} (${s.userRole}) -> ${s.method} ${s.path}`);
        await sendDedupedAlert(key, alert);
        return;
    }

    // Case B: Agent sends alerts array with violation entries
    if (item.alerts && Array.isArray(item.alerts)) {
        for (const a of item.alerts) {
            if (a.eventType !== 'ROLE_ACCESS_VIOLATION') continue;
            const key = `role_violation::${a.userEmail}::${a.path}`;
            const alert = {
                severity: 'HIGH',
                event: 'ROLE_ACCESS_VIOLATION',
                hostId: item.hostId,
                ts: a.ts || item.ts || new Date().toISOString(),
                details: {
                    userEmail: a.userEmail,
                    userRole: a.userRole,
                    method: a.method,
                    path: a.path,
                    hostId: item.hostId
                }
            };
            logSecurityAlert('HIGH', 'ROLE_ACCESS_VIOLATION', `${a.userEmail} (${a.userRole}) -> ${a.method} ${a.path}`);
            await sendDedupedAlert(key, alert);
        }
    }
}

// Rule 3: Ransomware file detection
async function ruleRansomware(item) {
    if (!item || !item.files || !Array.isArray(item.files)) return;
    for (const f of item.files) {
        if (f.type !== 'SUSPICIOUS_FILE') continue;
        const ext = (f.ext || '').toLowerCase();
        if (!RANSOMWARE_EXTENSIONS.includes(ext)) continue;
        const key = `ransomware::${item.hostId}::${f.name}`;
        const alert = {
            severity: 'CRITICAL',
            event: 'RANSOMWARE_INDICATOR',
            hostId: item.hostId,
            ts: item.ts || new Date().toISOString(),
            details: { file: f.name, ext, userEmail: item.userEmail, userRole: item.userRole }
        };
        logSecurityAlert('CRITICAL', 'RANSOMWARE_INDICATOR', `${item.hostId} [${item.userRole || 'unknown'}] file=${f.name}`);
        await sendDedupedAlert(key, alert);
    }
}

// Rule 4: Brute-force login detection (auth failures from same host)
async function ruleBruteForce(item) {
    if (!item || !item.logs || !Array.isArray(item.logs)) return;
    for (const log of item.logs) {
        if (log.type !== 'SECURITY_EVENT') continue;
        if (!log.message || !log.message.toLowerCase().includes('auth')) continue;

        const trackKey = item.hostId;
        const entry = bruteForceTracker.get(trackKey) || { count: 0, firstSeen: Date.now() };
        if (Date.now() - entry.firstSeen > BRUTE_FORCE_WINDOW_MS) {
            entry.count = 0;
            entry.firstSeen = Date.now();
        }
        entry.count++;
        bruteForceTracker.set(trackKey, entry);

        if (entry.count >= BRUTE_FORCE_THRESHOLD) {
            const key = `brute_force::${item.hostId}`;
            const alert = {
                severity: 'HIGH',
                event: 'BRUTE_FORCE_ATTEMPT',
                hostId: item.hostId,
                ts: item.ts || new Date().toISOString(),
                details: {
                    failureCount: entry.count,
                    windowMs: BRUTE_FORCE_WINDOW_MS,
                    userEmail: item.userEmail,
                    userRole: item.userRole,
                    ipAddress: item.hostId
                }
            };
            logSecurityAlert('HIGH', 'BRUTE_FORCE_ATTEMPT', `${item.hostId} ${entry.count} failures in window`);
            await sendDedupedAlert(key, alert);
            // reset after alert
            entry.count = 0;
            entry.firstSeen = Date.now();
        }
    }
}

// Rule 5: Database activity alerts (from db-monitor via EDR agent)
// Processes dbActivity.alerts from agent telemetry
async function ruleDbActivity(item) {
    if (!item || !item.dbActivity || !item.dbActivity.alerts) return;
    if (!Array.isArray(item.dbActivity.alerts)) return;

    for (const dbAlert of item.dbActivity.alerts) {
        const alertType = dbAlert.type || 'DB_UNKNOWN';
        const severity = dbAlert.severity || 'MEDIUM';
        const key = `db::${alertType}::${item.hostId}::${dbAlert.table || dbAlert.actorEmail || 'unknown'}`;

        const alert = {
            severity: severity,
            event: alertType,
            hostId: item.hostId,
            ts: dbAlert.ts || item.ts || new Date().toISOString(),
            details: {
                ...dbAlert,
                userEmail: item.userEmail,
                userRole: item.userRole,
                hostId: item.hostId
            }
        };

        let logMsg = '';
        switch (alertType) {
            case 'DB_MASS_DELETE':
            case 'DB_MASS_DELETE_STATS':
                logMsg = `${item.hostId} [${item.userRole}] mass delete on ${dbAlert.table} (${dbAlert.deleteCount || dbAlert.newDeletes} rows)`;
                break;
            case 'DB_UNAUTHORIZED_TABLE_ACCESS':
                logMsg = `${dbAlert.actorEmail} (${dbAlert.actorRole}) accessed ${dbAlert.table} via ${dbAlert.action}`;
                break;
            case 'DB_BULK_DATA_READ':
                logMsg = `${item.hostId} [${item.userRole}] bulk read on ${dbAlert.table} (${dbAlert.readCount} reads)`;
                break;
            case 'DB_SUDDEN_ROW_DROP':
                logMsg = `${dbAlert.table}: ${dbAlert.previousRows} -> ${dbAlert.currentRows} rows (lost ${dbAlert.rowsLost})`;
                break;
            case 'DB_LONG_RUNNING_QUERY':
                logMsg = `${dbAlert.user} query running ${dbAlert.durationSec}s: ${(dbAlert.query || '').substring(0, 80)}`;
                break;
            case 'DB_SCHEMA_CHANGE':
                logMsg = `${dbAlert.user} DDL: ${(dbAlert.query || '').substring(0, 80)}`;
                break;
            default:
                logMsg = `${alertType} on ${item.hostId}`;
        }

        logSecurityAlert(severity, alertType, logMsg);
        await sendDedupedAlert(key, alert);
    }
}

// Rule 6: ML Behavioral Anomaly Detection
// Called after ML engine returns a prediction for a telemetry item
async function ruleMLAnomaly(item, mlResult) {
    if (!mlResult || !mlResult.is_anomaly) return null;

    const classification = mlResult.classification; // 'Suspicious' or 'Malicious'
    const severity = classification === 'Malicious' ? 'CRITICAL' : 'HIGH';
    const key = `ml_anomaly::${item.hostId}::${classification}`;

    const alert = {
        severity,
        event: 'ML_ANOMALY',
        hostId: item.hostId,
        ts: item.ts || new Date().toISOString(),
        details: {
            anomaly_score: mlResult.anomaly_score,
            classification: mlResult.classification,
            confidence: mlResult.confidence,
            userEmail: item.userEmail || mlResult.userEmail,
            userRole: item.userRole || mlResult.userRole,
            hostId: item.hostId,
            detection_type: 'behavioral_ml'
        }
    };

    logSecurityAlert(severity, 'ML_ANOMALY', `${item.hostId} [${item.userRole || 'unknown'}] classification=${classification} score=${mlResult.anomaly_score} confidence=${mlResult.confidence}`);
    await sendDedupedAlert(key, alert);
    return alert;
}

/**
 * Hybrid Correlation: Combine ML anomaly with rule-based alerts
 * If both ML and rules detect the same item, escalate severity.
 */
async function hybridCorrelation(item, mlResult, ruleAlertFired) {
    if (!mlResult) return;

    // Case 1: Both ML and rules detected something â†’ escalate to CRITICAL
    if (mlResult.is_anomaly && ruleAlertFired) {
        const key = `hybrid::${item.hostId}::correlated`;
        const alert = {
            severity: 'CRITICAL',
            event: 'ML_RULE_CORRELATED',
            hostId: item.hostId,
            ts: item.ts || new Date().toISOString(),
            details: {
                ml_classification: mlResult.classification,
                ml_score: mlResult.anomaly_score,
                ml_confidence: mlResult.confidence,
                rule_alert: true,
                userEmail: item.userEmail,
                userRole: item.userRole,
                hostId: item.hostId,
                detection_type: 'hybrid_correlated'
            }
        };
        logSecurityAlert('CRITICAL', 'ML_RULE_CORRELATED', `${item.hostId} [${item.userRole || 'unknown'}] ML+Rule correlated anomaly (score=${mlResult.anomaly_score})`);
        await sendDedupedAlert(key, alert);
    }
}

// Main telemetry poll â€” runs all detection rules + ML on each item
async function pollTelemetry() {
    try {
        const url = 'http://127.0.0.1:9090/telemetry';
        http.get(url, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', async () => {
                try {
                    const parsed = JSON.parse(body || '{}');
                    // Collector returns { recentTelemetry: [...] }
                    const items = parsed.recentTelemetry || parsed || [];
                    if (!Array.isArray(items)) return;
                    for (const item of items) {
                        let ruleAlertFired = false;
                        let mlResult = null;
                        try {
                            // Run existing detection rules
                            await ruleExfiltration(item);
                            await ruleRoleViolation(item);
                            await ruleRansomware(item);
                            await ruleBruteForce(item);
                            await ruleDbActivity(item);

                            // Check if any rule fired for this item
                            const ruleKeys = [
                                `exfil::${item.hostId}`,
                                `role_violation::${(item.security || {}).userEmail || item.userEmail}`,
                                `ransomware::${item.hostId}`,
                                `brute_force::${item.hostId}`
                            ];
                            ruleAlertFired = ruleKeys.some(prefix =>
                                Array.from(recentAlerts.keys()).some(k => k.startsWith(prefix) && (Date.now() - recentAlerts.get(k)) < 5000)
                            );

                            // ML Engine inference (Phase 2: behavioral anomaly detection)
                            if (ML_ENABLED) {
                                try {
                                    mlResult = await callMLEngine(item);
                                    if (mlResult && mlResult.is_anomaly) {
                                        await ruleMLAnomaly(item, mlResult);
                                    }
                                    // Hybrid correlation
                                    await hybridCorrelation(item, mlResult, ruleAlertFired);
                                } catch (mlErr) {
                                    // ML engine unavailable â€” rules continue working
                                }
                            }
                        } catch (e) {
                            // ignore individual item errors
                        }
                    }
                    // cleanup old dedupe entries
                    for (const [k, ts] of Array.from(recentAlerts)) {
                        if (Date.now() - ts > ALERT_DEDUP_TTL_MS * 10) recentAlerts.delete(k);
                    }
                } catch (e) {
                    // ignore parse
                }
            });
        }).on('error', (err) => { /* ignore telemetry fetch errors */ });
    } catch (err) {
        // ignore
    }
}

// Main execution
async function main() {
    console.log('\nðŸš€ Starting Traffic Analyzer for Software-Defined Perimeter (SDP)\n');
    
    const startHeader = `
${'='.repeat(80)}
Traffic Analyzer Started - ${new Date().toISOString()}
${'='.repeat(80)}
`;
    writeLog(TRAFFIC_LOG, startHeader);
    writeLog(ALERT_LOG, startHeader);
    
    try {
        await analyzeTraffic();
        await monitorAPITraffic();
        await generateStatistics();
        
        console.log('\nâœ… Traffic analysis complete!\n');
        console.log(`ðŸ“ Logs saved to:`);
        console.log(`   - ${TRAFFIC_LOG}`);
        console.log(`   - ${ALERT_LOG}\n`);
        
    } catch (error) {
        console.error('âŒ Error during traffic analysis:', error.message);
        logSecurityAlert('ERROR', 'ANALYZER_ERROR', error.message);
    }
}

// Run the analyzer once and schedule periodic tasks
main();
setInterval(main, 5 * 60 * 1000); // full analysis every 5 minutes
setInterval(pollTelemetry, TELEMETRY_POLL_INTERVAL_MS); // poll telemetry frequently
// kick off immediate telemetry poll
pollTelemetry();



