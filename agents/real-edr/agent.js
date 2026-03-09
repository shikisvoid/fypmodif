// Real EDR Agent - Collects actual system telemetry
// Monitors: processes, files, network, system logs

const http = require('http');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration from environment
const HOST_ID = process.env.HOST_ID || 'unknown-endpoint';
const TARGET = process.env.TARGET || 'http://172.20.0.100:9090/ingest/telemetry';
const INTERVAL_MS = parseInt(process.env.INTERVAL_MS || '3000', 10);
const WATCH_DIR = process.env.WATCH_DIR || '/tmp';

// Role-aware configuration (Phase 2 integration with 8 user roles)
const USER_ROLE = process.env.USER_ROLE || 'unknown';
const USER_EMAIL = process.env.USER_EMAIL || 'unknown';

// Database monitoring configuration
const DB_HOST = process.env.DB_HOST || '';
const DB_PORT = parseInt(process.env.DB_PORT || '5432', 10);
const DB_USER = process.env.DB_USER || '';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_NAME = process.env.DB_NAME || '';
const DB_MONITOR_ENABLED = !!DB_HOST;

// Suspicious file extensions to monitor
const SUSPICIOUS_EXTENSIONS = ['.encrypted', '.lock', '.ransom', '.crypto', '.locked'];
// Suspicious IPs to flag
const SUSPICIOUS_IPS = ['8.8.8.8', '1.1.1.1', '185.220.101.1'];

// Initialize database monitor if configured
let dbMonitor = null;
if (DB_MONITOR_ENABLED) {
  try {
    const { DatabaseMonitor } = require('./db-monitor');
    dbMonitor = new DatabaseMonitor({
      host: DB_HOST,
      port: DB_PORT,
      user: DB_USER,
      password: DB_PASSWORD,
      database: DB_NAME,
      userRole: USER_ROLE,
      userEmail: USER_EMAIL
    });
    dbMonitor.init().then(ok => {
      if (ok) console.log(`[EDR Agent] ✅ Database monitor active → ${DB_HOST}:${DB_PORT}/${DB_NAME}`);
      else console.warn(`[EDR Agent] ⚠️ Database monitor failed to connect`);
    });
  } catch (err) {
    console.warn(`[EDR Agent] ⚠️ Database monitor not available: ${err.message}`);
  }
}

console.log(`[EDR Agent] Starting on ${HOST_ID}`);
console.log(`[EDR Agent] Role: ${USER_ROLE} | Email: ${USER_EMAIL}`);
console.log(`[EDR Agent] Target: ${TARGET}`);
console.log(`[EDR Agent] Interval: ${INTERVAL_MS}ms`);
console.log(`[EDR Agent] DB Monitor: ${DB_MONITOR_ENABLED ? `${DB_HOST}:${DB_PORT}/${DB_NAME}` : 'disabled'}`);

// Track previous state for change detection
let previousProcesses = new Set();
let previousFiles = new Map();

// Collect process activity
function collectProcessActivity() {
  try {
    const result = execSync('ps aux 2>/dev/null || ps -ef 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
    const lines = result.split('\n').slice(1).filter(l => l.trim());
    const processes = [];
    const currentProcesses = new Set();

    for (const line of lines.slice(0, 20)) { // Limit to 20 processes
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        const proc = {
          user: parts[0],
          pid: parts[1],
          cpu: parts[2] || '0',
          mem: parts[3] || '0',
          command: parts.slice(10).join(' ') || parts.slice(3).join(' ')
        };
        currentProcesses.add(proc.pid);
        
        // Flag new processes
        if (!previousProcesses.has(proc.pid)) {
          proc.isNew = true;
        }
        // Flag high resource usage
        if (parseFloat(proc.cpu) > 50) proc.highCpu = true;
        if (parseFloat(proc.mem) > 50) proc.highMem = true;
        
        processes.push(proc);
      }
    }
    previousProcesses = currentProcesses;
    return processes;
  } catch (e) {
    return [{ error: e.message }];
  }
}

// Collect file activity
function collectFileActivity() {
  const fileEvents = [];
  try {
    const files = fs.readdirSync(WATCH_DIR);
    const currentFiles = new Map();

    for (const file of files) {
      const fullPath = path.join(WATCH_DIR, file);
      try {
        const stats = fs.statSync(fullPath);
        currentFiles.set(file, stats.mtimeMs);

        // Check for suspicious extensions
        const ext = path.extname(file).toLowerCase();
        if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
          fileEvents.push({ type: 'SUSPICIOUS_FILE', file, ext, path: fullPath });
        }

        // Detect new or modified files
        if (!previousFiles.has(file)) {
          fileEvents.push({ type: 'FILE_CREATED', file, path: fullPath });
        } else if (previousFiles.get(file) !== stats.mtimeMs) {
          fileEvents.push({ type: 'FILE_MODIFIED', file, path: fullPath });
        }
      } catch (e) { /* skip inaccessible files */ }
    }

    // Detect deleted files
    for (const [file] of previousFiles) {
      if (!currentFiles.has(file)) {
        fileEvents.push({ type: 'FILE_DELETED', file });
      }
    }
    previousFiles = currentFiles;
  } catch (e) {
    fileEvents.push({ error: e.message });
  }
  return fileEvents;
}

// Collect network activity
function collectNetworkActivity() {
  const netEvents = [];
  try {
    // Try netstat first, then ss
    let result;
    try {
      result = execSync('netstat -tun 2>/dev/null | head -30', { encoding: 'utf8', timeout: 5000 });
    } catch {
      result = execSync('ss -tun 2>/dev/null | head -30', { encoding: 'utf8', timeout: 5000 });
    }

    const lines = result.split('\n').slice(1).filter(l => l.trim());
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 5) {
        const localAddr = parts[3] || '';
        const foreignAddr = parts[4] || '';
        const conn = { local: localAddr, foreign: foreignAddr, state: parts[5] || 'UNKNOWN' };

        // Extract destination IP
        const dstMatch = foreignAddr.match(/^([0-9.]+):/);
        if (dstMatch) {
          conn.dst = dstMatch[1];
          // Flag suspicious IPs
          if (SUSPICIOUS_IPS.includes(conn.dst)) {
            conn.suspicious = true;
            netEvents.push({ type: 'SUSPICIOUS_CONNECTION', dst: conn.dst, ...conn });
          }
        }
        netEvents.push(conn);
      }
    }

    // Also check running processes for network commands to suspicious IPs
    try {
      const psResult = execSync('ps aux 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
      for (const ip of SUSPICIOUS_IPS) {
        if (psResult.includes(ip)) {
          netEvents.push({ type: 'SUSPICIOUS_CONNECTION', dst: ip, suspicious: true, source: 'process_cmdline' });
        }
      }
    } catch (e) { /* ignore */ }

  } catch (e) {
    netEvents.push({ error: e.message });
  }
  return netEvents.slice(0, 15); // Limit entries
}

// Collect system logs
function collectSystemLogs() {
  const logEvents = [];
  const logFiles = ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages', '/var/log/secure'];

  for (const logFile of logFiles) {
    try {
      if (fs.existsSync(logFile)) {
        const result = execSync(`tail -5 ${logFile} 2>/dev/null`, { encoding: 'utf8', timeout: 3000 });
        const lines = result.split('\n').filter(l => l.trim());
        for (const line of lines) {
          // Flag security-related events
          if (/fail|error|denied|invalid|attack/i.test(line)) {
            logEvents.push({ type: 'SECURITY_EVENT', source: logFile, message: line.substring(0, 200) });
          }
        }
      }
    } catch (e) { /* skip inaccessible logs */ }
  }
  return logEvents;
}

// Send telemetry to central server
function sendTelemetry(telemetry) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(telemetry);
    const url = new URL(TARGET);

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
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });

    req.on('error', reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.write(data);
    req.end();
  });
}

// Collect all telemetry and send
async function collectAndSend() {
  const telemetry = {
    hostId: HOST_ID,
    ts: new Date().toISOString(),
    // Role-aware fields (Phase 2 integration)
    userRole: USER_ROLE,
    userEmail: USER_EMAIL,
    source: 'edr-agent',
    processes: collectProcessActivity(),
    files: collectFileActivity(),
    network: collectNetworkActivity(),
    logs: collectSystemLogs()
  };

  // Database monitoring — collect real DB activity instead of watching empty dirs
  if (dbMonitor) {
    try {
      const dbActivity = await dbMonitor.collectDatabaseActivity();
      telemetry.dbActivity = dbActivity;

      // Promote DB alerts into the top-level alerts array
      if (dbActivity.alerts && dbActivity.alerts.length > 0) {
        console.log(`[EDR Agent] 🗄️  ${dbActivity.alerts.length} DB alert(s) for role=${USER_ROLE}`);
      }
    } catch (err) {
      telemetry.dbActivity = { error: err.message, alerts: [] };
    }
  }

  // Add net field for compatibility with traffic-analyzer detection
  const suspiciousNet = telemetry.network.find(n => n.suspicious);
  if (suspiciousNet) {
    telemetry.net = { dst: suspiciousNet.dst };
  }

  // Count alerts
  const alerts = [];
  telemetry.files.filter(f => f.type === 'SUSPICIOUS_FILE').forEach(f => alerts.push(f));
  telemetry.network.filter(n => n.suspicious).forEach(n => alerts.push(n));
  telemetry.logs.filter(l => l.type === 'SECURITY_EVENT').forEach(l => alerts.push(l));
  // Include database alerts
  if (telemetry.dbActivity && telemetry.dbActivity.alerts) {
    telemetry.dbActivity.alerts.forEach(a => alerts.push(a));
  }

  if (alerts.length > 0) {
    telemetry.alerts = alerts;
    // Tag alerts with role context
    telemetry.alerts.forEach(a => {
      a.userRole = USER_ROLE;
      a.userEmail = USER_EMAIL;
    });
    console.log(`[EDR Agent] ⚠️  ${alerts.length} alert(s) detected for role=${USER_ROLE}`);
  }

  try {
    await sendTelemetry(telemetry);
    const dbInfo = telemetry.dbActivity ? `, ${(telemetry.dbActivity.auditLogs || []).length} audit logs` : '';
    console.log(`[EDR Agent] ✅ [${USER_ROLE}] Telemetry sent: ${telemetry.processes.length} procs, ${telemetry.files.length} file events, ${telemetry.network.length} net conns${dbInfo}`);
  } catch (err) {
    console.error(`[EDR Agent] ❌ Failed to send telemetry: ${err.message}`);
  }
}

// Main loop
console.log(`[EDR Agent] Starting telemetry collection...`);
collectAndSend(); // Initial collection
setInterval(collectAndSend, INTERVAL_MS);

