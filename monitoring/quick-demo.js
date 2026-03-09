// Quick Software-Defined Perimeter (SDP) Demo - Fast metrics generation
// This script validates identity-aware access through the SDP gateway.

const fs = require('fs');
const http = require('http');

const LOG_FILE = '/logs/comprehensive-network-monitor.log';
const GATEWAY_HOST = process.env.SDP_GATEWAY_HOST || 'api-gateway';
const GATEWAY_PORT = parseInt(process.env.SDP_GATEWAY_PORT || '8080', 10);

const header = `
================================================================================
SDP LIVE DEMO - STARTED
================================================================================
Timestamp: ${new Date().toISOString()}
Purpose: Demonstrate identity-aware access control in real-time
View in: Prometheus (http://localhost:9091) | Grafana (http://localhost:3002)
================================================================================

`;

fs.writeFileSync(LOG_FILE, header);

function log(level, category, message, data = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] [${level}] [${category}] ${message} ${JSON.stringify(data)}`;
  console.log(logEntry);
  fs.appendFileSync(LOG_FILE, logEntry + '\n');
}

function httpTest(path) {
  return new Promise((resolve) => {
    const req = http.request({
      hostname: GATEWAY_HOST,
      port: GATEWAY_PORT,
      path,
      method: 'GET',
      timeout: 2000
    }, (res) => {
      res.resume();
      const isAllowed = res.statusCode >= 200 && res.statusCode < 300;
      if (res.statusCode === 401 || res.statusCode === 403) {
        return resolve('BLOCKED');
      }
      return resolve(isAllowed ? 'REACHABLE' : 'BLOCKED');
    });

    req.on('error', () => resolve('BLOCKED'));
    req.on('timeout', () => {
      req.destroy();
      resolve('BLOCKED');
    });
    req.end();
  });
}

async function runQuickDemo() {
  const demoStart = Date.now();

  log('INFO', 'DEMO_START', 'Running SDP demo', { timestamp: new Date().toISOString() });

  const test1 = await httpTest('/api/patients');
  log(test1 === 'BLOCKED' ? 'INFO' : 'ERROR', 'SDP_TEST',
    `${test1 === 'BLOCKED' ? 'PASS' : 'FAIL'}: Unauthenticated patients API denied`,
    { target: '/api/patients', expected: 'BLOCKED', actual: test1, passed: test1 === 'BLOCKED' });

  const test2 = await httpTest('/api/appointments');
  log(test2 === 'BLOCKED' ? 'INFO' : 'ERROR', 'SDP_TEST',
    `${test2 === 'BLOCKED' ? 'PASS' : 'FAIL'}: Unauthenticated appointments API denied`,
    { target: '/api/appointments', expected: 'BLOCKED', actual: test2, passed: test2 === 'BLOCKED' });

  const test3 = await httpTest('/api/login');
  log(test3 === 'REACHABLE' ? 'INFO' : 'ERROR', 'SDP_TEST',
    `${test3 === 'REACHABLE' ? 'PASS' : 'FAIL'}: Public login endpoint reachable`,
    { target: '/api/login', expected: 'REACHABLE', actual: test3, passed: test3 === 'REACHABLE' });

  const test4 = await httpTest('/api/mfa/verify');
  log(test4 === 'REACHABLE' ? 'INFO' : 'ERROR', 'SDP_TEST',
    `${test4 === 'REACHABLE' ? 'PASS' : 'FAIL'}: Public MFA endpoint reachable`,
    { target: '/api/mfa/verify', expected: 'REACHABLE', actual: test4, passed: test4 === 'REACHABLE' });

  const test5 = await httpTest('/api/monitoring/health');
  log(test5 === 'REACHABLE' ? 'INFO' : 'ERROR', 'SDP_TEST',
    `${test5 === 'REACHABLE' ? 'PASS' : 'FAIL'}: Health endpoint reachable`,
    { target: '/api/monitoring/health', expected: 'REACHABLE', actual: test5, passed: test5 === 'REACHABLE' });

  const test6 = await httpTest('/health');
  log(test6 === 'REACHABLE' ? 'INFO' : 'ERROR', 'SDP_TEST',
    `${test6 === 'REACHABLE' ? 'PASS' : 'FAIL'}: SDP gateway health reachable`,
    { target: '/health', expected: 'REACHABLE', actual: test6, passed: test6 === 'REACHABLE' });

  const tests = [
    test1 === 'BLOCKED',
    test2 === 'BLOCKED',
    test3 === 'REACHABLE',
    test4 === 'REACHABLE',
    test5 === 'REACHABLE',
    test6 === 'REACHABLE'
  ];

  const passed = tests.filter(Boolean).length;
  const failed = tests.length - passed;
  const blocked = [test1, test2].filter(t => t === 'BLOCKED').length;
  const allowed = [test3, test4, test5, test6].filter(t => t === 'REACHABLE').length;
  const violations = tests.filter(t => !t).length;

  const securityScore = violations === 0 ? 100 : Math.max(0, 100 - (violations * 20));
  const passRate = ((passed / tests.length) * 100).toFixed(1);

  log('INFO', 'DEMO_COMPLETE', 'Demo cycle completed', {
    total_tests: tests.length,
    passed,
    failed,
    pass_rate: passRate,
    allowed_connections: allowed,
    blocked_attempts: blocked,
    security_violations: violations,
    security_score: securityScore,
    duration_ms: Date.now() - demoStart
  });

  log('INFO', 'SECURITY_SCORE', 'Security posture', {
    score: securityScore,
    violations,
    status: securityScore === 100 ? 'EXCELLENT' : 'NEEDS_ATTENTION'
  });
}

console.log('\n' + '='.repeat(60));
console.log('SDP LIVE DEMO');
console.log('='.repeat(60));
console.log('Running tests every 10 seconds...');
console.log('View in Prometheus: http://localhost:9091');
console.log('View in Grafana: http://localhost:3002');
console.log('='.repeat(60) + '\n');

runQuickDemo();
setInterval(runQuickDemo, 10000);
