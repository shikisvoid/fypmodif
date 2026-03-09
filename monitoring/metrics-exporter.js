// Prometheus Metrics Exporter for Network Monitoring
// Exposes network monitoring metrics in Prometheus format

const http = require('http');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORT = process.env.METRICS_PORT ? parseInt(process.env.METRICS_PORT, 10) : 9090;

// Logs directory (Windows-friendly default)
const DEFAULT_LOG_DIR = process.platform === 'win32' ? 'C:\\logs' : '/logs';
const LOG_DIR = process.env.LOG_DIR || DEFAULT_LOG_DIR;
const LOG_FILE = path.join(LOG_DIR, 'comprehensive-network-monitor.log');
const TELEMETRY_LOG = path.join(LOG_DIR, 'telemetry.log');

// Ensure log directory exists and is writable
try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
} catch (err) {
  console.error(`Failed to create log directory ${LOG_DIR}:`, err.message);
}

// Recent telemetry cache (in-memory)
const RECENT_TELEMETRY_MAX = 100;
const recentTelemetry = [];

// Metrics storage
let metrics = {
  isolation_tests_total: 0,
  isolation_tests_passed: 0,
  isolation_tests_failed: 0,
  allowed_connections: 0,
  blocked_attempts: 0,
  security_violations: 0,
  security_score: 100.0,
  telemetry_received: 0,
  last_update: Date.now()
};

// Parse log file to extract metrics
function parseLogFile() {
  try {
    if (!fs.existsSync(LOG_FILE)) {
      console.log('Log file not found, using default metrics');
      return;
    }

    const logContent = fs.readFileSync(LOG_FILE, 'utf8');
    const lines = logContent.split('\n');

    // Reset metrics
    metrics.isolation_tests_total = 0;
    metrics.isolation_tests_passed = 0;
    metrics.isolation_tests_failed = 0;
    metrics.allowed_connections = 0;
    metrics.blocked_attempts = 0;
    metrics.security_violations = 0;

    lines.forEach(line => {
      try {
        // Extract JSON data from log lines
        const jsonMatch = line.match(/\{.*\}/);
        if (!jsonMatch) return;

        const data = JSON.parse(jsonMatch[0]);

        // Parse isolation test results
        if (line.includes('[SDP_TEST]')) {
          metrics.isolation_tests_total++;
          if (data.passed === true) {
            metrics.isolation_tests_passed++;
          } else if (data.passed === false) {
            metrics.isolation_tests_failed++;
          }
        }

        // Parse traffic analysis
        if (line.includes('[ACCESS_ALLOWED]')) {
          metrics.allowed_connections++;
        }
        if (line.includes('[ACCESS_BLOCKED]')) {
          metrics.blocked_attempts++;
        }

        // Parse security violations
        if (line.includes('[SECURITY_VIOLATION]')) {
          metrics.security_violations++;
        }

        // Parse security score
        if (line.includes('[SECURITY_SCORE]') && data.score) {
          metrics.security_score = parseFloat(data.score);
        }

      } catch (e) {
        // Skip malformed lines
      }
    });

    metrics.last_update = Date.now();
    console.log(`[${new Date().toISOString()}] Metrics updated:`, metrics);

  } catch (error) {
    console.error('Error parsing log file:', error.message);
  }
}

// Generate Prometheus metrics format
function generateMetrics() {
  const timestamp = Date.now();
  
  return `# HELP sdp_policy_tests_total Total number of SDP access control tests
# TYPE sdp_policy_tests_total counter
sdp_policy_tests_total ${metrics.isolation_tests_total} ${timestamp}

# HELP sdp_policy_tests_passed Number of passed isolation tests
# TYPE sdp_policy_tests_passed counter
sdp_policy_tests_passed ${metrics.isolation_tests_passed} ${timestamp}

# HELP sdp_policy_tests_failed Number of failed isolation tests
# TYPE sdp_policy_tests_failed counter
sdp_policy_tests_failed ${metrics.isolation_tests_failed} ${timestamp}

# HELP network_allowed_connections Total number of allowed network connections
# TYPE network_allowed_connections counter
network_allowed_connections ${metrics.allowed_connections} ${timestamp}

# HELP network_blocked_attempts Total number of blocked connection attempts
# TYPE network_blocked_attempts counter
network_blocked_attempts ${metrics.blocked_attempts} ${timestamp}

# HELP network_security_violations Total number of security violations detected
# TYPE network_security_violations counter
network_security_violations ${metrics.security_violations} ${timestamp}

# HELP network_security_score Overall network security score (0-100)
# TYPE network_security_score gauge
network_security_score ${metrics.security_score} ${timestamp}

# HELP network_telemetry_received_total Total telemetry messages received
# TYPE network_telemetry_received_total counter
network_telemetry_received_total ${metrics.telemetry_received} ${timestamp}

# HELP sdp_policy_pass_rate Percentage of isolation tests passed
# TYPE sdp_policy_pass_rate gauge
sdp_policy_pass_rate ${metrics.isolation_tests_total > 0 ? ((metrics.isolation_tests_passed / metrics.isolation_tests_total) * 100).toFixed(2) : 0} ${timestamp}

# HELP network_monitoring_last_update Timestamp of last metrics update
# TYPE network_monitoring_last_update gauge
network_monitoring_last_update ${metrics.last_update} ${timestamp}
`;
}

// HTTP server for Prometheus scraping
const server = http.createServer((req, res) => {
  if (req.url === '/metrics') {
    parseLogFile();
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(generateMetrics());
  } else if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'healthy', uptime: process.uptime() }));
  } else if (req.url === '/telemetry' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ recentTelemetry }));
  } else if (req.url === '/ingest/telemetry' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        data.receivedAt = new Date().toISOString();
        fs.appendFile(TELEMETRY_LOG, JSON.stringify(data) + '\n', (err) => {
          if (err) console.error('Failed to write telemetry:', err);
        });
        recentTelemetry.push(data);
        if (recentTelemetry.length > RECENT_TELEMETRY_MAX) recentTelemetry.shift();
        metrics.telemetry_received = (metrics.telemetry_received || 0) + 1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid json' }));
      }
    });
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

// Global error handlers for better diagnostics
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.stack || err.message || err);
  try { fs.appendFileSync(path.join(LOG_DIR, 'error.log'), `${new Date().toISOString()} UNCaught: ${err.stack || err}\n`); } catch {}
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
  try { fs.appendFileSync(path.join(LOG_DIR, 'error.log'), `${new Date().toISOString()} UnhandledRejection: ${reason}\n`); } catch {}
});

server.on('error', (err) => {
  console.error('Server error:', err.message || err);
  if (err && err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} already in use. Stop other services or set METRICS_PORT env to a different port.`);
  }
  try { fs.appendFileSync(path.join(LOG_DIR, 'error.log'), `${new Date().toISOString()} ServerError: ${err.stack || err}\n`); } catch {}
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n${'='.repeat(80)}`);
  console.log('PROMETHEUS METRICS EXPORTER');
  console.log(`${'='.repeat(80)}\n`);
  console.log(`Listening on port ${PORT}`);
  console.log(`Metrics endpoint: http://0.0.0.0:${PORT}/metrics`);
  console.log(`Health endpoint: http://0.0.0.0:${PORT}/health`);
  console.log(`\nWaiting for Prometheus to scrape metrics...\n`);
});

// Parse metrics every 30 seconds
setInterval(parseLogFile, 30000);

// Initial parse
parseLogFile();


