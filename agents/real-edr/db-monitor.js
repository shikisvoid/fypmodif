// Database Monitor Module for EDR Agent
// Connects to PostgreSQL and monitors for suspicious database activity

const { Pool } = require('pg');

// Role-based table access policy — which tables each role legitimately accesses
const ROLE_TABLE_POLICY = {
  admin:          ['*'], // admin can access everything
  doctor:         ['patients', 'appointments', 'lab_tests', 'prescriptions', 'vitals', 'files', 'users', 'notifications'],
  nurse:          ['patients', 'appointments', 'vitals', 'notifications'],
  receptionist:   ['patients', 'appointments', 'billing', 'billing_services', 'notifications'],
  lab_technician: ['patients', 'lab_tests', 'lab_samples', 'lab_results', 'lab_audit_logs', 'notifications'],
  pharmacist:     ['patients', 'prescriptions', 'pharmacy_inventory', 'notifications'],
  accountant:     ['billing', 'billing_services', 'patients', 'notifications'],
  patient:        ['patients', 'appointments', 'billing', 'notifications']
};

// Thresholds for suspicious activity
const MASS_DELETE_THRESHOLD = 5;      // 5+ deletes in one poll = suspicious
const BULK_READ_THRESHOLD = 20;       // 20+ reads in one poll = potential exfiltration
const LONG_QUERY_THRESHOLD_SEC = 30;  // queries running > 30s

class DatabaseMonitor {
  constructor(config) {
    this.pool = new Pool({
      host: config.host,
      port: config.port || 5432,
      user: config.user,
      password: config.password,
      database: config.database,
      max: 2,            // minimal pool for monitoring
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    });
    this.userRole = config.userRole || 'unknown';
    this.userEmail = config.userEmail || 'unknown';
    this.lastPollTime = new Date(Date.now() - 60000).toISOString(); // start 1 min ago
    this.previousTableStats = null;
    this.connected = false;
  }

  async init() {
    try {
      const client = await this.pool.connect();
      client.release();
      this.connected = true;
      console.log(`[DB-Monitor] Connected to PostgreSQL (role=${this.userRole})`);
      return true;
    } catch (err) {
      console.error(`[DB-Monitor] Connection failed: ${err.message}`);
      this.connected = false;
      return false;
    }
  }

  // Query recent audit_logs since last poll
  async getRecentAuditLogs() {
    try {
      const result = await this.pool.query(
        `SELECT al.id, al.action, al.resource_type, al.resource_id,
                al.status, al.remote_addr, al.created_at,
                u.email AS actor_email, u.role AS actor_role
         FROM audit_logs al
         LEFT JOIN users u ON al.actor_id = u.id
         WHERE al.created_at > $1
         ORDER BY al.created_at DESC
         LIMIT 100`,
        [this.lastPollTime]
      );
      this.lastPollTime = new Date().toISOString();
      return result.rows;
    } catch (err) {
      return [{ error: err.message }];
    }
  }

  // Query active database sessions/queries
  async getActiveQueries() {
    try {
      const result = await this.pool.query(
        `SELECT pid, usename, datname, state, query,
                EXTRACT(EPOCH FROM (now() - query_start)) AS duration_sec,
                client_addr, wait_event_type
         FROM pg_stat_activity
         WHERE datname = $1
           AND pid != pg_backend_pid()
           AND state != 'idle'
         ORDER BY query_start`,
        [this.pool.options.database]
      );
      return result.rows;
    } catch (err) {
      return [{ error: err.message }];
    }
  }

  // Get table-level statistics for change detection
  async getTableStats() {
    try {
      const result = await this.pool.query(
        `SELECT relname AS table_name,
                seq_scan, idx_scan,
                n_tup_ins AS inserts,
                n_tup_upd AS updates,
                n_tup_del AS deletes,
                n_live_tup AS live_rows
         FROM pg_stat_user_tables
         ORDER BY relname`
      );
      return result.rows;
    } catch (err) {
      return [{ error: err.message }];
    }
  }

  // Detect suspicious patterns in audit logs
  analyzeAuditLogs(logs) {
    const alerts = [];
    if (!Array.isArray(logs) || logs.length === 0) return alerts;

    // Count actions by type
    const deleteCounts = {};
    const readCounts = {};

    for (const log of logs) {
      if (log.error) continue;
      const table = (log.resource_type || '').toLowerCase();
      const action = (log.action || '').toUpperCase();

      // Track deletes per table
      if (action === 'DELETE') {
        deleteCounts[table] = (deleteCounts[table] || 0) + 1;
      }
      // Track reads per table
      if (action === 'READ' || action === 'EXPORT') {
        readCounts[table] = (readCounts[table] || 0) + 1;
      }

      // Check role-based table access violations
      const actorRole = (log.actor_role || '').toLowerCase();
      if (actorRole && actorRole !== 'admin') {
        const allowedTables = ROLE_TABLE_POLICY[actorRole] || [];
        if (!allowedTables.includes('*') && !allowedTables.includes(table) && table) {
          alerts.push({
            type: 'DB_UNAUTHORIZED_TABLE_ACCESS',
            severity: 'HIGH',
            actorEmail: log.actor_email,
            actorRole: actorRole,
            table: table,
            action: action,
            ts: log.created_at
          });
        }
      }
    }

    // Check mass deletion threshold
    for (const [table, count] of Object.entries(deleteCounts)) {
      if (count >= MASS_DELETE_THRESHOLD) {
        alerts.push({
          type: 'DB_MASS_DELETE',
          severity: 'CRITICAL',
          table,
          deleteCount: count,
          ts: new Date().toISOString()
        });
      }
    }

    // Check bulk read threshold (potential exfiltration)
    for (const [table, count] of Object.entries(readCounts)) {
      if (count >= BULK_READ_THRESHOLD) {
        alerts.push({
          type: 'DB_BULK_DATA_READ',
          severity: 'HIGH',
          table,
          readCount: count,
          ts: new Date().toISOString()
        });
      }
    }

    return alerts;
  }

  // Detect suspicious active queries
  analyzeActiveQueries(queries) {
    const alerts = [];
    if (!Array.isArray(queries)) return alerts;

    for (const q of queries) {
      if (q.error) continue;

      // Long-running queries
      if (q.duration_sec > LONG_QUERY_THRESHOLD_SEC) {
        alerts.push({
          type: 'DB_LONG_RUNNING_QUERY',
          severity: 'MEDIUM',
          query: (q.query || '').substring(0, 200),
          durationSec: Math.round(q.duration_sec),
          user: q.usename,
          clientAddr: q.client_addr,
          ts: new Date().toISOString()
        });
      }

      // Detect DDL operations (schema changes)
      const queryUpper = (q.query || '').toUpperCase();
      if (queryUpper.includes('DROP TABLE') || queryUpper.includes('ALTER TABLE') ||
          queryUpper.includes('TRUNCATE') || queryUpper.includes('DROP DATABASE')) {
        alerts.push({
          type: 'DB_SCHEMA_CHANGE',
          severity: 'CRITICAL',
          query: (q.query || '').substring(0, 200),
          user: q.usename,
          clientAddr: q.client_addr,
          ts: new Date().toISOString()
        });
      }
    }
    return alerts;
  }

  // Detect table stat anomalies (sudden drops in row counts = mass deletion)
  analyzeTableStats(currentStats) {
    const alerts = [];
    if (!Array.isArray(currentStats) || !this.previousTableStats) {
      this.previousTableStats = currentStats;
      return alerts;
    }

    const prevMap = {};
    for (const s of this.previousTableStats) {
      if (s.table_name) prevMap[s.table_name] = s;
    }

    for (const curr of currentStats) {
      if (curr.error || !curr.table_name) continue;
      const prev = prevMap[curr.table_name];
      if (!prev) continue;

      // Sudden row count drop (> 10 rows deleted between polls)
      const rowDiff = (prev.live_rows || 0) - (curr.live_rows || 0);
      if (rowDiff > 10) {
        alerts.push({
          type: 'DB_SUDDEN_ROW_DROP',
          severity: 'HIGH',
          table: curr.table_name,
          previousRows: prev.live_rows,
          currentRows: curr.live_rows,
          rowsLost: rowDiff,
          ts: new Date().toISOString()
        });
      }

      // Sudden increase in deletes
      const deleteDiff = (curr.deletes || 0) - (prev.deletes || 0);
      if (deleteDiff > MASS_DELETE_THRESHOLD) {
        alerts.push({
          type: 'DB_MASS_DELETE_STATS',
          severity: 'CRITICAL',
          table: curr.table_name,
          newDeletes: deleteDiff,
          ts: new Date().toISOString()
        });
      }
    }

    this.previousTableStats = currentStats;
    return alerts;
  }

  // Main collection method - called by agent.js
  async collectDatabaseActivity() {
    if (!this.connected) {
      const ok = await this.init();
      if (!ok) return { error: 'Not connected to database', alerts: [] };
    }

    try {
      const [auditLogs, activeQueries, tableStats] = await Promise.all([
        this.getRecentAuditLogs(),
        this.getActiveQueries(),
        this.getTableStats()
      ]);

      // Run analysis
      const auditAlerts = this.analyzeAuditLogs(auditLogs);
      const queryAlerts = this.analyzeActiveQueries(activeQueries);
      const statsAlerts = this.analyzeTableStats(tableStats);
      const allAlerts = [...auditAlerts, ...queryAlerts, ...statsAlerts];

      // Tag all alerts with role context
      for (const a of allAlerts) {
        a.monitorRole = this.userRole;
        a.monitorEmail = this.userEmail;
      }

      return {
        auditLogs: auditLogs.slice(0, 20), // Limit payload size
        activeQueries: activeQueries.slice(0, 10),
        tableStats: tableStats.map(s => ({
          table: s.table_name,
          liveRows: s.live_rows,
          inserts: s.inserts,
          updates: s.updates,
          deletes: s.deletes,
          seqScans: s.seq_scan
        })),
        alerts: allAlerts,
        monitorRole: this.userRole,
        pollTime: new Date().toISOString()
      };
    } catch (err) {
      console.error(`[DB-Monitor] Collection error: ${err.message}`);
      return { error: err.message, alerts: [] };
    }
  }

  async shutdown() {
    try { await this.pool.end(); } catch (e) { /* ignore */ }
  }
}

module.exports = { DatabaseMonitor, ROLE_TABLE_POLICY };
