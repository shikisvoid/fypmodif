// SDP Demonstration Script
// This script runs continuous tests to demonstrate network isolation in real-time
// Results are visible in Prometheus and Grafana

const { execSync } = require('child_process');
const fs = require('fs');

const LOG_FILE = '/logs/comprehensive-network-monitor.log';
const DEMO_INTERVAL = 10000; // Run demo every 10 seconds

// Test scenarios to demonstrate SDP
const DEMO_SCENARIOS = [
  {
    name: 'Frontend Isolation Test',
    description: 'Frontend should NOT access backend database directly',
    tests: [
      { source: 'hospital-frontend', target: '172.20.0.10', port: 5432, service: 'database', expected: 'BLOCKED', severity: 'CRITICAL' },
      { source: 'hospital-frontend', target: '172.20.0.30', port: 3001, service: 'encryption', expected: 'BLOCKED', severity: 'CRITICAL' }
    ]
  },
  {
    name: 'Backend Access Test',
    description: 'Backend API should access database and encryption',
    tests: [
      { source: 'hospital-backend', target: '172.20.0.10', port: 5432, service: 'database', expected: 'REACHABLE', severity: 'INFO' },
      { source: 'hospital-backend', target: '172.20.0.30', port: 3001, service: 'encryption', expected: 'REACHABLE', severity: 'INFO' }
    ]
  },
  {
    name: 'IAM Isolation Test',
    description: 'IAM should NOT access backend services directly',
    tests: [
      { source: 'hospital-iam', target: '172.20.0.10', port: 5432, service: 'database', expected: 'BLOCKED', severity: 'CRITICAL' },
      { source: 'hospital-iam', target: '172.20.0.30', port: 3001, service: 'encryption', expected: 'BLOCKED', severity: 'CRITICAL' }
    ]
  },
  {
    name: 'Cross-Network Communication',
    description: 'Frontend services should communicate via Backend API only',
    tests: [
      { source: 'hospital-frontend', target: '172.21.0.20', port: 3000, service: 'backend-api', expected: 'REACHABLE', severity: 'INFO' },
      { source: 'hospital-iam', target: '172.21.0.20', port: 3000, service: 'backend-api', expected: 'REACHABLE', severity: 'INFO' }
    ]
  }
];

// Statistics tracking
let stats = {
  total_tests: 0,
  passed_tests: 0,
  failed_tests: 0,
  blocked_attempts: 0,
  allowed_connections: 0,
  security_violations: 0,
  demo_runs: 0
};

function log(level, category, message, data = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] [${level}] [${category}] ${message} ${JSON.stringify(data)}`;
  console.log(logEntry);
  
  try {
    fs.appendFileSync(LOG_FILE, logEntry + '\n');
  } catch (error) {
    console.error('Failed to write to log file:', error.message);
  }
}

function testConnection(source, target, port) {
  try {
    // Use nc (netcat) with 1 second timeout for faster tests
    execSync(`docker exec ${source} timeout 1 nc -zv ${target} ${port}`, {
      stdio: 'pipe',
      timeout: 1500
    });
    return 'REACHABLE';
  } catch (error) {
    return 'BLOCKED';
  }
}

function runDemoScenario(scenario) {
  log('INFO', 'DEMO_SCENARIO', `Starting: ${scenario.name}`, { description: scenario.description });
  
  let scenarioPassed = 0;
  let scenarioFailed = 0;
  
  scenario.tests.forEach(test => {
    stats.total_tests++;
    
    const actual = testConnection(test.source, test.target, test.port);
    const passed = (actual === test.expected);
    
    if (passed) {
      stats.passed_tests++;
      scenarioPassed++;
    } else {
      stats.failed_tests++;
      scenarioFailed++;
    }
    
    // Track allowed vs blocked
    if (actual === 'BLOCKED') {
      stats.blocked_attempts++;
    } else {
      stats.allowed_connections++;
    }
    
    // Check for security violations (unexpected access)
    if (test.expected === 'BLOCKED' && actual === 'REACHABLE') {
      stats.security_violations++;
      log('ERROR', 'SECURITY_VIOLATION', `Unexpected access detected!`, {
        source: test.source,
        target: test.target,
        port: test.port,
        service: test.service,
        expected: test.expected,
        actual: actual,
        severity: 'CRITICAL'
      });
    }
    
    // Log test result
    const logLevel = passed ? 'INFO' : 'ERROR';
    const category = passed ? 'ISOLATION_TEST' : 'ISOLATION_TEST';
    
    log(logLevel, category, `${passed ? 'PASS' : 'FAIL'}: ${scenario.name} - ${test.service}`, {
      source: test.source,
      target: test.target,
      port: test.port,
      service: test.service,
      expected: test.expected,
      actual: actual,
      passed: passed,
      severity: test.severity
    });
  });
  
  log('INFO', 'DEMO_SUMMARY', `Scenario completed: ${scenario.name}`, {
    total: scenario.tests.length,
    passed: scenarioPassed,
    failed: scenarioFailed,
    passRate: `${((scenarioPassed / scenario.tests.length) * 100).toFixed(1)}%`
  });
}

function runFullDemo() {
  stats.demo_runs++;
  
  log('INFO', 'DEMO_START', '========== SDP DEMONSTRATION ==========', {
    run: stats.demo_runs,
    timestamp: new Date().toISOString()
  });
  
  // Run all demo scenarios
  DEMO_SCENARIOS.forEach(scenario => {
    runDemoScenario(scenario);
  });
  
  // Calculate security score
  const securityScore = stats.security_violations === 0 ? 100 : Math.max(0, 100 - (stats.security_violations * 10));
  const passRate = stats.total_tests > 0 ? ((stats.passed_tests / stats.total_tests) * 100).toFixed(1) : 0;
  
  // Log comprehensive statistics
  log('INFO', 'DEMO_COMPLETE', 'Demonstration run completed', {
    demo_run: stats.demo_runs,
    total_tests: stats.total_tests,
    passed: stats.passed_tests,
    failed: stats.failed_tests,
    pass_rate: `${passRate}%`,
    allowed_connections: stats.allowed_connections,
    blocked_attempts: stats.blocked_attempts,
    security_violations: stats.security_violations,
    security_score: securityScore
  });
  
  log('INFO', 'SECURITY_SCORE', 'Current security posture', {
    score: securityScore,
    violations: stats.security_violations,
    status: securityScore === 100 ? 'EXCELLENT' : securityScore >= 80 ? 'GOOD' : 'NEEDS_ATTENTION'
  });
  
  console.log(`\n${'='.repeat(80)}`);
  console.log(`DEMO RUN #${stats.demo_runs} COMPLETE`);
  console.log(`Tests: ${stats.passed_tests}/${stats.total_tests} passed (${passRate}%)`);
  console.log(`Security Score: ${securityScore}/100`);
  console.log(`Security Violations: ${stats.security_violations}`);
  console.log(`${'='.repeat(80)}\n`);
}

// Main execution
console.log('\n' + '='.repeat(80));
console.log('SDP DEMONSTRATION - CONTINUOUS MODE');
console.log('='.repeat(80));
console.log('This script demonstrates network isolation in real-time.');
console.log('View results in:');
console.log('  â€¢ Prometheus: http://localhost:9091');
console.log('  â€¢ Grafana: http://localhost:3002');
console.log('  â€¢ Logs: comprehensive-network-monitor.log');
console.log('='.repeat(80) + '\n');

// Run initial demo immediately
runFullDemo();

// Continue running demos at regular intervals
setInterval(runFullDemo, DEMO_INTERVAL);


