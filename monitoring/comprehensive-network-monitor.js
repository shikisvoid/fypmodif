/**
 * Comprehensive Network Monitoring System
 * Consolidates all network monitoring into a single detailed log file
 * Tracks: Traffic, Security Events, Access Control, Isolation Tests, Anomalies
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const LOG_DIR = '/logs';
const COMPREHENSIVE_LOG = path.join(LOG_DIR, 'comprehensive-network-monitor.log');
const STATS_LOG = path.join(LOG_DIR, 'network-statistics.log');

// Network configuration
const NETWORK_CONFIG = {
  backend: {
    subnet: '172.20.0.0/24',
    containers: {
      'hospital-db': '172.20.0.10',
      'hospital-backend': '172.20.0.20',
      'hospital-encryption': '172.20.0.30',
      'hospital-monitor': '172.20.0.100'
    }
  },
  frontend: {
    subnet: '172.21.0.0/24',
    containers: {
      'hospital-backend': '172.21.0.20',
      'hospital-iam': '172.21.0.40',
      'hospital-frontend': '172.21.0.50',
      'hospital-monitor': '172.21.0.100'
    }
  }
};

// Access control rules
const ACCESS_RULES = {
  'hospital-frontend': {
    allowed: ['172.21.0.20', '172.21.0.40'], // Backend API, IAM
    blocked: ['172.20.0.10', '172.20.0.30'], // Database, Encryption
    network: 'frontend'
  },
  'hospital-backend': {
    allowed: ['172.20.0.10', '172.20.0.30', '172.21.0.40', '172.21.0.50'],
    blocked: [],
    network: 'both'
  },
  'hospital-iam': {
    allowed: ['172.21.0.20', '172.21.0.50'], // Backend API, Frontend
    blocked: ['172.20.0.10', '172.20.0.30'], // Database, Encryption
    network: 'frontend'
  },
  'hospital-db': {
    allowed: ['172.20.0.20'], // Only Backend API
    blocked: ['172.21.0.40', '172.21.0.50'], // IAM, Frontend
    network: 'backend'
  },
  'hospital-encryption': {
    allowed: ['172.20.0.20'], // Only Backend API
    blocked: ['172.21.0.40', '172.21.0.50'], // IAM, Frontend
    network: 'backend'
  }
};

// Statistics tracking
const stats = {
  totalTests: 0,
  passedTests: 0,
  failedTests: 0,
  blockedAttempts: 0,
  allowedConnections: 0,
  securityViolations: 0,
  startTime: new Date().toISOString()
};

// Logging functions
function log(level, category, message, details = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    category,
    message,
    details
  };
  
  const logLine = `[${timestamp}] [${level}] [${category}] ${message} ${JSON.stringify(details)}\n`;
  fs.appendFileSync(COMPREHENSIVE_LOG, logLine);
  
  // Also log to console for real-time monitoring
  console.log(logLine.trim());
}

function logSeparator(title) {
  const separator = '='.repeat(80);
  const line = `\n${separator}\n${title}: ${new Date().toISOString()}\n${separator}\n`;
  fs.appendFileSync(COMPREHENSIVE_LOG, line);
  console.log(line);
}

// Network testing functions
function testConnection(source, target, port = 80) {
  try {
    const result = execSync(
      `docker exec ${source} timeout 2 nc -zv ${target} ${port} 2>&1`,
      { encoding: 'utf-8', timeout: 3000 }
    );
    return result.includes('open') || result.includes('succeeded');
  } catch (error) {
    return false;
  }
}

function testPing(source, target) {
  try {
    const result = execSync(
      `docker exec ${source} timeout 2 ping -c 1 ${target} 2>&1`,
      { encoding: 'utf-8', timeout: 3000 }
    );
    return result.includes('1 packets received') || result.includes('1 received');
  } catch (error) {
    return false;
  }
}

// Isolation tests
function runIsolationTests() {
  logSeparator('NETWORK ISOLATION TESTS');
  
  const tests = [
    {
      name: 'Frontend to Database (Should FAIL)',
      source: 'hospital-frontend',
      target: '172.20.0.10',
      port: 5432,
      shouldSucceed: false,
      reason: 'Frontend is isolated from backend network'
    },
    {
      name: 'Frontend to Backend API (Should SUCCEED)',
      source: 'hospital-frontend',
      target: '172.21.0.20',
      port: 3000,
      shouldSucceed: true,
      reason: 'Frontend can access backend API on frontend network'
    },
    {
      name: 'Frontend to Encryption (Should FAIL)',
      source: 'hospital-frontend',
      target: '172.20.0.30',
      port: 3001,
      shouldSucceed: false,
      reason: 'Frontend is isolated from encryption service'
    },
    {
      name: 'Backend to Database (Should SUCCEED)',
      source: 'hospital-backend',
      target: '172.20.0.10',
      port: 5432,
      shouldSucceed: true,
      reason: 'Backend API can access database'
    },
    {
      name: 'Backend to Encryption (Should SUCCEED)',
      source: 'hospital-backend',
      target: '172.20.0.30',
      port: 3001,
      shouldSucceed: true,
      reason: 'Backend API can access encryption service'
    },
    {
      name: 'IAM to Database (Should FAIL)',
      source: 'hospital-iam',
      target: '172.20.0.10',
      port: 5432,
      shouldSucceed: false,
      reason: 'IAM is isolated from backend network'
    },
    {
      name: 'IAM to Backend API (Should SUCCEED)',
      source: 'hospital-iam',
      target: '172.21.0.20',
      port: 3000,
      shouldSucceed: true,
      reason: 'IAM can access backend API on frontend network'
    }
  ];

  let passed = 0;
  let failed = 0;

  tests.forEach(test => {
    stats.totalTests++;
    const result = testConnection(test.source, test.target, test.port);
    const success = result === test.shouldSucceed;

    if (success) {
      passed++;
      stats.passedTests++;
      log('INFO', 'SDP_TEST', `PASS: ${test.name}`, {
        source: test.source,
        target: test.target,
        port: test.port,
        expected: test.shouldSucceed ? 'REACHABLE' : 'BLOCKED',
        actual: result ? 'REACHABLE' : 'BLOCKED',
        reason: test.reason,
        passed: true
      });
    } else {
      failed++;
      stats.failedTests++;
      log('ERROR', 'SDP_TEST', `FAIL: ${test.name}`, {
        source: test.source,
        target: test.target,
        port: test.port,
        expected: test.shouldSucceed ? 'REACHABLE' : 'BLOCKED',
        actual: result ? 'REACHABLE' : 'BLOCKED',
        reason: test.reason,
        passed: false
      });
    }

    // Track security metrics
    if (result && !test.shouldSucceed) {
      stats.securityViolations++;
      log('CRITICAL', 'SECURITY_VIOLATION', `Unauthorized access detected: ${test.source} -> ${test.target}`, {
        source: test.source,
        target: test.target,
        port: test.port,
        severity: 'HIGH'
      });
    } else if (!result && !test.shouldSucceed) {
      stats.blockedAttempts++;
    } else if (result && test.shouldSucceed) {
      stats.allowedConnections++;
    }
  });

  log('INFO', 'ISOLATION_SUMMARY', `Isolation tests completed: ${passed} passed, ${failed} failed`, {
    total: tests.length,
    passed,
    failed,
    passRate: ((passed / tests.length) * 100).toFixed(1) + '%'
  });
}

// Traffic monitoring
function monitorTraffic() {
  logSeparator('TRAFFIC MONITORING');

  Object.keys(ACCESS_RULES).forEach(container => {
    const rules = ACCESS_RULES[container];

    log('INFO', 'TRAFFIC_ANALYSIS', `Analyzing traffic for ${container}`, {
      network: rules.network,
      allowedTargets: rules.allowed.length,
      blockedTargets: rules.blocked.length
    });

    // Test allowed connections
    rules.allowed.forEach(target => {
      const reachable = testPing(container, target);
      if (reachable) {
        log('INFO', 'ACCESS_ALLOWED', `${container} -> ${target}`, {
          source: container,
          target,
          status: 'ALLOWED',
          reason: 'Permitted by network policy'
        });
        stats.allowedConnections++;
      } else {
        log('WARNING', 'ACCESS_BLOCKED', `${container} -> ${target} (should be allowed)`, {
          source: container,
          target,
          status: 'BLOCKED',
          expected: 'ALLOWED',
          severity: 'MEDIUM'
        });
      }
    });

    // Test blocked connections
    rules.blocked.forEach(target => {
      const reachable = testPing(container, target);
      if (!reachable) {
        log('INFO', 'ACCESS_BLOCKED', `${container} -> ${target}`, {
          source: container,
          target,
          status: 'BLOCKED',
          reason: 'Blocked by SDP access control'
        });
        stats.blockedAttempts++;
      } else {
        log('CRITICAL', 'SECURITY_VIOLATION', `${container} -> ${target} (should be blocked)`, {
          source: container,
          target,
          status: 'ALLOWED',
          expected: 'BLOCKED',
          severity: 'HIGH'
        });
        stats.securityViolations++;
      }
    });
  });
}

// Network topology analysis
function analyzeNetworkTopology() {
  logSeparator('NETWORK TOPOLOGY ANALYSIS');

  log('INFO', 'TOPOLOGY', 'Backend Network (172.20.0.0/24)', {
    subnet: NETWORK_CONFIG.backend.subnet,
    containers: Object.keys(NETWORK_CONFIG.backend.containers),
    isolation: 'Internal only - no direct frontend access'
  });

  log('INFO', 'TOPOLOGY', 'Frontend Network (172.21.0.0/24)', {
    subnet: NETWORK_CONFIG.frontend.subnet,
    containers: Object.keys(NETWORK_CONFIG.frontend.containers),
    isolation: 'Public-facing services'
  });

  log('INFO', 'TOPOLOGY', 'Bridge Services', {
    services: ['hospital-backend', 'hospital-monitor'],
    role: 'Connect both networks with controlled access'
  });
}

// Security posture assessment
function assessSecurityPosture() {
  logSeparator('SECURITY POSTURE ASSESSMENT');

  const checks = [
    {
      name: 'Database Isolation',
      check: () => !testPing('hospital-frontend', '172.20.0.10'),
      severity: 'CRITICAL'
    },
    {
      name: 'Encryption Service Isolation',
      check: () => !testPing('hospital-frontend', '172.20.0.30'),
      severity: 'CRITICAL'
    },
    {
      name: 'Backend API Accessibility from Frontend',
      check: () => testPing('hospital-frontend', '172.21.0.20'),
      severity: 'HIGH'
    },
    {
      name: 'IAM Accessibility from Frontend',
      check: () => testPing('hospital-frontend', '172.21.0.40'),
      severity: 'HIGH'
    },
    {
      name: 'Database Accessibility from Backend',
      check: () => testPing('hospital-backend', '172.20.0.10'),
      severity: 'CRITICAL'
    }
  ];

  let passed = 0;
  let failed = 0;

  checks.forEach(check => {
    const result = check.check();
    if (result) {
      passed++;
      log('INFO', 'SECURITY_CHECK', `PASS: ${check.name}`, {
        check: check.name,
        severity: check.severity,
        status: 'PASS'
      });
    } else {
      failed++;
      log('ERROR', 'SECURITY_CHECK', `FAIL: ${check.name}`, {
        check: check.name,
        severity: check.severity,
        status: 'FAIL'
      });
    }
  });

  const securityScore = ((passed / checks.length) * 100).toFixed(1);
  log('INFO', 'SECURITY_SCORE', `Overall security score: ${securityScore}%`, {
    total: checks.length,
    passed,
    failed,
    score: securityScore
  });
}

// Generate statistics report
function generateStatistics() {
  logSeparator('NETWORK MONITORING STATISTICS');

  const duration = (new Date() - new Date(stats.startTime)) / 1000;

  const statsReport = {
    monitoringPeriod: {
      start: stats.startTime,
      end: new Date().toISOString(),
      durationSeconds: duration.toFixed(2)
    },
    isolationTests: {
      total: stats.totalTests,
      passed: stats.passedTests,
      failed: stats.failedTests,
      passRate: stats.totalTests > 0 ? ((stats.passedTests / stats.totalTests) * 100).toFixed(1) + '%' : 'N/A'
    },
    trafficAnalysis: {
      allowedConnections: stats.allowedConnections,
      blockedAttempts: stats.blockedAttempts,
      securityViolations: stats.securityViolations
    },
    networkHealth: {
      status: stats.securityViolations === 0 ? 'HEALTHY' : 'COMPROMISED',
      isolationEffectiveness: stats.blockedAttempts > 0 ? 'EFFECTIVE' : 'UNKNOWN'
    }
  };

  log('INFO', 'STATISTICS', 'Monitoring statistics generated', statsReport);

  // Write detailed statistics to separate file
  const statsContent = `
================================================================================
NETWORK MONITORING STATISTICS REPORT
Generated: ${new Date().toISOString()}
================================================================================

MONITORING PERIOD:
  Start Time:        ${statsReport.monitoringPeriod.start}
  End Time:          ${statsReport.monitoringPeriod.end}
  Duration:          ${statsReport.monitoringPeriod.durationSeconds} seconds

ISOLATION TESTS:
  Total Tests:       ${statsReport.isolationTests.total}
  Passed:            ${statsReport.isolationTests.passed}
  Failed:            ${statsReport.isolationTests.failed}
  Pass Rate:         ${statsReport.isolationTests.passRate}

TRAFFIC ANALYSIS:
  Allowed Connections:    ${statsReport.trafficAnalysis.allowedConnections}
  Blocked Attempts:       ${statsReport.trafficAnalysis.blockedAttempts}
  Security Violations:    ${statsReport.trafficAnalysis.securityViolations}

NETWORK HEALTH:
  Overall Status:         ${statsReport.networkHealth.status}
  Isolation Effectiveness: ${statsReport.networkHealth.isolationEffectiveness}

NETWORK CONFIGURATION:
  Backend Network:   172.20.0.0/24
    - hospital-db (172.20.0.10)
    - hospital-backend (172.20.0.20)
    - hospital-encryption (172.20.0.30)
    - hospital-monitor (172.20.0.100)

  Frontend Network:  172.21.0.0/24
    - hospital-backend (172.21.0.20)
    - hospital-iam (172.21.0.40)
    - hospital-frontend (172.21.0.50)
    - hospital-monitor (172.21.0.100)

SECURITY POSTURE:
  ${stats.securityViolations === 0 ? 'âœ“' : 'âœ—'} No security violations detected
  ${stats.blockedAttempts > 0 ? 'âœ“' : 'âœ—'} Network isolation is functioning
  ${stats.passedTests === stats.totalTests ? 'âœ“' : 'âœ—'} All isolation tests passed

================================================================================
`;

  fs.writeFileSync(STATS_LOG, statsContent);
  console.log(`\nâœ“ Statistics report written to ${STATS_LOG}`);
}

// Main execution
function main() {
  console.log('\n' + '='.repeat(80));
  console.log('COMPREHENSIVE NETWORK MONITORING SYSTEM');
  console.log('Hospital Management System - Software-Defined Perimeter (SDP)');
  console.log('='.repeat(80) + '\n');

  // Initialize log file
  const header = `
${'='.repeat(80)}
COMPREHENSIVE NETWORK MONITORING LOG
Started: ${new Date().toISOString()}
${'='.repeat(80)}
`;
  fs.writeFileSync(COMPREHENSIVE_LOG, header);

  log('INFO', 'SYSTEM', 'Network monitoring started', {
    logFile: COMPREHENSIVE_LOG,
    statsFile: STATS_LOG
  });

  // Run all monitoring tasks
  try {
    analyzeNetworkTopology();
    runIsolationTests();
    monitorTraffic();
    assessSecurityPosture();
    generateStatistics();

    log('INFO', 'SYSTEM', 'Network monitoring completed successfully', {
      totalTests: stats.totalTests,
      securityViolations: stats.securityViolations
    });

    console.log('\n' + '='.repeat(80));
    console.log('MONITORING COMPLETE');
    console.log('='.repeat(80));
    console.log(`\nLogs written to:`);
    console.log(`  - Comprehensive Log: ${COMPREHENSIVE_LOG}`);
    console.log(`  - Statistics Report: ${STATS_LOG}`);
    console.log(`\nSummary:`);
    console.log(`  Total Tests: ${stats.totalTests}`);
    console.log(`  Passed: ${stats.passedTests}`);
    console.log(`  Failed: ${stats.failedTests}`);
    console.log(`  Security Violations: ${stats.securityViolations}`);
    console.log(`  Status: ${stats.securityViolations === 0 ? 'SECURE' : 'COMPROMISED'}\n`);

  } catch (error) {
    log('ERROR', 'SYSTEM', 'Monitoring failed', {
      error: error.message,
      stack: error.stack
    });
    console.error('Error during monitoring:', error);
    process.exit(1);
  }
}

// Run monitoring
main();


