/**
 * System & API Monitoring Service
 * 
 * Tracks server-level metrics:
 * - CPU usage
 * - Memory (RAM) usage
 * - Disk space
 * - Node.js event loop delay
 * - Server uptime
 * - API response times
 * - Database monitoring
 */

const os = require('os');
const winstonLogger = require('./winstonLogger');
const db = require('../db');

// Metrics storage
const systemMetrics = {
  startTime: Date.now(),
  
  // System resources
  cpu: { usage: 0, cores: os.cpus().length },
  memory: { used: 0, total: os.totalmem(), free: 0, usagePercent: 0 },
  
  // Event loop
  eventLoop: { delay: 0, samples: [] },
  
  // API metrics
  api: {
    totalRequests: 0,
    requestsByEndpoint: {},
    responseTimesByEndpoint: {},
    statusCodes: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 },
    errorsByEndpoint: {},
    avgResponseTime: 0
  },
  
  // Database metrics
  database: {
    connectionPool: { active: 0, idle: 0, total: 0 },
    slowQueries: [],
    queryCount: 0,
    avgQueryTime: 0
  }
};

// ================== CPU MONITORING ==================

let lastCPUMeasure = process.cpuUsage();
let lastCPUTime = Date.now();

function updateCPUUsage() {
  const currentUsage = process.cpuUsage(lastCPUMeasure);
  const currentTime = Date.now();
  const timeDelta = (currentTime - lastCPUTime) * 1000; // Convert to microseconds
  
  const cpuPercent = ((currentUsage.user + currentUsage.system) / timeDelta) * 100;
  systemMetrics.cpu.usage = Math.min(100, Math.round(cpuPercent * 100) / 100);
  
  lastCPUMeasure = process.cpuUsage();
  lastCPUTime = currentTime;
}

// ================== MEMORY MONITORING ==================

function updateMemoryUsage() {
  const used = process.memoryUsage();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  
  systemMetrics.memory = {
    heapUsed: used.heapUsed,
    heapTotal: used.heapTotal,
    external: used.external,
    rss: used.rss,
    total: totalMem,
    free: freeMem,
    used: totalMem - freeMem,
    usagePercent: Math.round(((totalMem - freeMem) / totalMem) * 100 * 100) / 100
  };
}

// ================== EVENT LOOP MONITORING ==================

let lastLoopTime = Date.now();

function measureEventLoopDelay() {
  const expectedDelay = 100; // Check every 100ms
  const now = Date.now();
  const actualDelay = now - lastLoopTime - expectedDelay;
  
  systemMetrics.eventLoop.delay = Math.max(0, actualDelay);
  systemMetrics.eventLoop.samples.push({ timestamp: now, delay: actualDelay });
  
  // Keep only last 60 samples (1 minute at 1 sample/sec)
  if (systemMetrics.eventLoop.samples.length > 60) {
    systemMetrics.eventLoop.samples = systemMetrics.eventLoop.samples.slice(-60);
  }
  
  lastLoopTime = now;
}

// Start event loop monitoring
setInterval(measureEventLoopDelay, 100);

// ================== API MONITORING ==================

function recordAPIRequest(method, endpoint, statusCode, responseTimeMs, userId) {
  const key = `${method}:${endpoint}`;
  
  // Total requests
  systemMetrics.api.totalRequests++;
  
  // By endpoint
  systemMetrics.api.requestsByEndpoint[key] = (systemMetrics.api.requestsByEndpoint[key] || 0) + 1;
  
  // Response times
  if (!systemMetrics.api.responseTimesByEndpoint[key]) {
    systemMetrics.api.responseTimesByEndpoint[key] = [];
  }
  systemMetrics.api.responseTimesByEndpoint[key].push(responseTimeMs);
  
  // Keep only last 100 response times per endpoint
  if (systemMetrics.api.responseTimesByEndpoint[key].length > 100) {
    systemMetrics.api.responseTimesByEndpoint[key] = 
      systemMetrics.api.responseTimesByEndpoint[key].slice(-100);
  }
  
  // Status codes
  if (statusCode >= 200 && statusCode < 300) systemMetrics.api.statusCodes['2xx']++;
  else if (statusCode >= 300 && statusCode < 400) systemMetrics.api.statusCodes['3xx']++;
  else if (statusCode >= 400 && statusCode < 500) systemMetrics.api.statusCodes['4xx']++;
  else if (statusCode >= 500) systemMetrics.api.statusCodes['5xx']++;
  
  // Track errors
  if (statusCode >= 400) {
    systemMetrics.api.errorsByEndpoint[key] = (systemMetrics.api.errorsByEndpoint[key] || 0) + 1;
  }
  
  // Log to API log file
  winstonLogger.logAPI({
    method, endpoint, statusCode, responseTime: responseTimeMs, userId
  });
}

// Calculate average response time
function getAverageResponseTime(endpoint) {
  if (!endpoint) {
    // Overall average
    const allTimes = Object.values(systemMetrics.api.responseTimesByEndpoint).flat();
    if (allTimes.length === 0) return 0;
    return Math.round(allTimes.reduce((a, b) => a + b, 0) / allTimes.length);
  }
  
  const times = systemMetrics.api.responseTimesByEndpoint[endpoint] || [];
  if (times.length === 0) return 0;
  return Math.round(times.reduce((a, b) => a + b, 0) / times.length);
}

// ================== DATABASE MONITORING ==================

async function updateDatabaseMetrics() {
  try {
    // Get connection pool stats if available
    const pool = db.pool;
    if (pool) {
      systemMetrics.database.connectionPool = {
        total: pool.totalCount || 0,
        idle: pool.idleCount || 0,
        waiting: pool.waitingCount || 0
      };
    }
  } catch (err) {
    // Pool stats not available
  }
}

function recordSlowQuery(query, durationMs, params) {
  if (durationMs > 500) { // Slow query threshold: 500ms
    const entry = {
      query: query.substring(0, 200), // Truncate for logging
      duration: durationMs,
      timestamp: new Date().toISOString()
    };

    systemMetrics.database.slowQueries.push(entry);

    // Keep only last 100 slow queries
    if (systemMetrics.database.slowQueries.length > 100) {
      systemMetrics.database.slowQueries = systemMetrics.database.slowQueries.slice(-100);
    }

    // Log slow query
    winstonLogger.errorLogger.warn('SLOW_QUERY', entry);
  }

  systemMetrics.database.queryCount++;
}

// ================== PERIODIC UPDATES ==================

// Update CPU and memory every 5 seconds
setInterval(() => {
  updateCPUUsage();
  updateMemoryUsage();
  updateDatabaseMetrics();
}, 5000);

// Initial update
updateCPUUsage();
updateMemoryUsage();

// ================== PROMETHEUS METRICS ==================

function getPrometheusMetrics() {
  const lines = [];
  const uptime = (Date.now() - systemMetrics.startTime) / 1000;

  // Uptime
  lines.push('# HELP nodejs_uptime_seconds Process uptime in seconds');
  lines.push('# TYPE nodejs_uptime_seconds gauge');
  lines.push(`nodejs_uptime_seconds ${uptime}`);

  // CPU
  lines.push('# HELP nodejs_cpu_usage_percent Process CPU usage percentage');
  lines.push('# TYPE nodejs_cpu_usage_percent gauge');
  lines.push(`nodejs_cpu_usage_percent ${systemMetrics.cpu.usage}`);

  // Memory
  lines.push('# HELP nodejs_memory_heap_used_bytes Process heap memory used');
  lines.push('# TYPE nodejs_memory_heap_used_bytes gauge');
  lines.push(`nodejs_memory_heap_used_bytes ${systemMetrics.memory.heapUsed || 0}`);

  lines.push('# HELP nodejs_memory_heap_total_bytes Process heap memory total');
  lines.push('# TYPE nodejs_memory_heap_total_bytes gauge');
  lines.push(`nodejs_memory_heap_total_bytes ${systemMetrics.memory.heapTotal || 0}`);

  lines.push('# HELP system_memory_usage_percent System memory usage percentage');
  lines.push('# TYPE system_memory_usage_percent gauge');
  lines.push(`system_memory_usage_percent ${systemMetrics.memory.usagePercent}`);

  // Event loop
  lines.push('# HELP nodejs_eventloop_lag_seconds Event loop lag in seconds');
  lines.push('# TYPE nodejs_eventloop_lag_seconds gauge');
  lines.push(`nodejs_eventloop_lag_seconds ${systemMetrics.eventLoop.delay / 1000}`);

  // API metrics
  lines.push('# HELP http_requests_total Total HTTP requests');
  lines.push('# TYPE http_requests_total counter');
  lines.push(`http_requests_total ${systemMetrics.api.totalRequests}`);

  lines.push('# HELP http_request_duration_ms_avg Average HTTP response time in ms');
  lines.push('# TYPE http_request_duration_ms_avg gauge');
  lines.push(`http_request_duration_ms_avg ${getAverageResponseTime()}`);

  // Status codes
  lines.push('# HELP http_responses_by_status HTTP responses by status code class');
  lines.push('# TYPE http_responses_by_status counter');
  for (const [code, count] of Object.entries(systemMetrics.api.statusCodes)) {
    lines.push(`http_responses_by_status{status="${code}"} ${count}`);
  }

  // Database
  lines.push('# HELP db_slow_queries_total Total slow queries (>500ms)');
  lines.push('# TYPE db_slow_queries_total counter');
  lines.push(`db_slow_queries_total ${systemMetrics.database.slowQueries.length}`);

  return lines.join('\n');
}

// ================== JSON METRICS FOR DASHBOARD ==================

function getSystemMetrics() {
  return {
    uptime: Math.floor((Date.now() - systemMetrics.startTime) / 1000),
    uptimeFormatted: formatUptime(Date.now() - systemMetrics.startTime),
    cpu: systemMetrics.cpu,
    memory: {
      ...systemMetrics.memory,
      heapUsedMB: Math.round((systemMetrics.memory.heapUsed || 0) / 1024 / 1024),
      heapTotalMB: Math.round((systemMetrics.memory.heapTotal || 0) / 1024 / 1024),
      systemUsedMB: Math.round((systemMetrics.memory.used || 0) / 1024 / 1024),
      systemTotalMB: Math.round((systemMetrics.memory.total || 0) / 1024 / 1024)
    },
    eventLoop: {
      currentDelay: systemMetrics.eventLoop.delay,
      avgDelay: systemMetrics.eventLoop.samples.length > 0
        ? Math.round(systemMetrics.eventLoop.samples.reduce((a, b) => a + b.delay, 0) / systemMetrics.eventLoop.samples.length)
        : 0
    },
    api: {
      totalRequests: systemMetrics.api.totalRequests,
      avgResponseTime: getAverageResponseTime(),
      statusCodes: systemMetrics.api.statusCodes,
      topEndpoints: getTopEndpoints(10),
      errorRate: systemMetrics.api.totalRequests > 0
        ? Math.round(((systemMetrics.api.statusCodes['4xx'] + systemMetrics.api.statusCodes['5xx']) / systemMetrics.api.totalRequests) * 100 * 100) / 100
        : 0
    },
    database: {
      ...systemMetrics.database,
      slowQueryCount: systemMetrics.database.slowQueries.length,
      recentSlowQueries: systemMetrics.database.slowQueries.slice(-5)
    }
  };
}

function formatUptime(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
  if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  return `${minutes}m ${seconds % 60}s`;
}

function getTopEndpoints(limit = 10) {
  return Object.entries(systemMetrics.api.requestsByEndpoint)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([endpoint, count]) => ({
      endpoint,
      requests: count,
      avgResponseTime: getAverageResponseTime(endpoint),
      errors: systemMetrics.api.errorsByEndpoint[endpoint] || 0
    }));
}

// ================== API MONITORING MIDDLEWARE ==================

function apiMonitoringMiddleware(req, res, next) {
  const startTime = Date.now();

  // Capture when response finishes
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const endpoint = req.route?.path || req.path;
    recordAPIRequest(req.method, endpoint, res.statusCode, duration, req.user?.userId);
  });

  next();
}

module.exports = {
  // Metrics
  getSystemMetrics, getPrometheusMetrics, systemMetrics,

  // Recording functions
  recordAPIRequest, recordSlowQuery,

  // Middleware
  apiMonitoringMiddleware,

  // Helpers
  getAverageResponseTime, getTopEndpoints
};

