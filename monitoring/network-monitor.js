// Network Traffic Monitor for Software-Defined Perimeter (SDP)
// Logs all network movements, attempts, and security events

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Configuration
const LOG_DIR = '/logs';
const CONTAINERS = [
    { name: 'hospital-db', network: 'backend', ip: '172.20.0.10' },
    { name: 'hospital-backend', network: 'both', ip: '172.20.0.20/172.21.0.20' },
    { name: 'hospital-encryption', network: 'backend', ip: '172.20.0.30' },
    { name: 'hospital-iam', network: 'frontend', ip: '172.21.0.40' },
    { name: 'hospital-frontend', network: 'frontend', ip: '172.21.0.50' }
];

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Log file paths
const LOG_FILES = {
    traffic: path.join(LOG_DIR, 'network-traffic.log'),
    security: path.join(LOG_DIR, 'security-events.log'),
    access: path.join(LOG_DIR, 'access-attempts.log'),
    isolation: path.join(LOG_DIR, 'isolation-tests.log'),
    summary: path.join(LOG_DIR, 'daily-summary.log')
};

// Initialize log files with headers
function initializeLogs() {
    const timestamp = new Date().toISOString();
    
    writeLog(LOG_FILES.traffic, `\n${'='.repeat(80)}\nNetwork Traffic Monitor Started: ${timestamp}\n${'='.repeat(80)}\n`);
    writeLog(LOG_FILES.security, `\n${'='.repeat(80)}\nSecurity Event Monitor Started: ${timestamp}\n${'='.repeat(80)}\n`);
    writeLog(LOG_FILES.access, `\n${'='.repeat(80)}\nAccess Attempt Monitor Started: ${timestamp}\n${'='.repeat(80)}\n`);
    writeLog(LOG_FILES.isolation, `\n${'='.repeat(80)}\nIsolation Test Monitor Started: ${timestamp}\n${'='.repeat(80)}\n`);
    
    console.log('âœ“ Network monitoring initialized');
    console.log(`âœ“ Logs directory: ${LOG_DIR}`);
}

// Write to log file
function writeLog(file, message) {
    fs.appendFileSync(file, message + '\n');
}

// Format log entry
function formatLogEntry(level, category, message, metadata = {}) {
    const timestamp = new Date().toISOString();
    const meta = Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : '';
    return `[${timestamp}] [${level}] [${category}] ${message} ${meta}`;
}

// Log network traffic
function logTraffic(source, destination, protocol, port, status) {
    const entry = formatLogEntry('INFO', 'TRAFFIC', 
        `${source} -> ${destination}:${port} (${protocol})`, 
        { status, timestamp: Date.now() }
    );
    writeLog(LOG_FILES.traffic, entry);
}

// Log security event
function logSecurityEvent(eventType, severity, description, details = {}) {
    const entry = formatLogEntry(severity, 'SECURITY', 
        `${eventType}: ${description}`, 
        details
    );
    writeLog(LOG_FILES.security, entry);
}

// Log access attempt
function logAccessAttempt(source, target, allowed, reason) {
    const entry = formatLogEntry(allowed ? 'INFO' : 'WARN', 'ACCESS', 
        `${source} -> ${target}`, 
        { allowed, reason }
    );
    writeLog(LOG_FILES.access, entry);
}

// Log isolation test
function logIsolationTest(testName, source, target, expected, actual, passed) {
    const entry = formatLogEntry(passed ? 'INFO' : 'ERROR', 'ISOLATION', 
        `Test: ${testName}`, 
        { source, target, expected, actual, passed }
    );
    writeLog(LOG_FILES.isolation, entry);
}

// Test SDP access control
async function testNetworkIsolation() {
    console.log('\nðŸ” Running SDP access control tests...\n');
    
    const tests = [
        {
            name: 'Frontend to Database (Should FAIL)',
            source: 'hospital-frontend',
            target: '172.20.0.10',
            shouldSucceed: false
        },
        {
            name: 'Frontend to Backend (Should SUCCEED)',
            source: 'hospital-frontend',
            target: '172.21.0.20',
            shouldSucceed: true
        },
        {
            name: 'Backend to Database (Should SUCCEED)',
            source: 'hospital-backend',
            target: '172.20.0.10',
            shouldSucceed: true
        },
        {
            name: 'Frontend to Encryption (Should FAIL)',
            source: 'hospital-frontend',
            target: '172.20.0.30',
            shouldSucceed: false
        },
        {
            name: 'Backend to Encryption (Should SUCCEED)',
            source: 'hospital-backend',
            target: '172.20.0.30',
            shouldSucceed: true
        }
    ];
    
    for (const test of tests) {
        try {
            const cmd = `docker exec ${test.source} ping -c 1 -W 2 ${test.target}`;
            const { stdout, stderr } = await execPromise(cmd);
            const succeeded = !stderr && stdout.includes('1 packets transmitted, 1 received');
            const passed = succeeded === test.shouldSucceed;
            
            logIsolationTest(
                test.name,
                test.source,
                test.target,
                test.shouldSucceed ? 'REACHABLE' : 'BLOCKED',
                succeeded ? 'REACHABLE' : 'BLOCKED',
                passed
            );
            
            if (passed) {
                console.log(`  âœ“ ${test.name}: PASS`);
                logSecurityEvent('SDP_TEST', 'INFO', `${test.name} passed`, { test });
            } else {
                console.log(`  âœ— ${test.name}: FAIL`);
                logSecurityEvent('SDP_TEST', 'ERROR', `${test.name} failed`, { test });
            }
        } catch (error) {
            const passed = !test.shouldSucceed; // If command failed and we expected it to fail
            logIsolationTest(
                test.name,
                test.source,
                test.target,
                test.shouldSucceed ? 'REACHABLE' : 'BLOCKED',
                'BLOCKED',
                passed
            );
            
            if (passed) {
                console.log(`  âœ“ ${test.name}: PASS (blocked as expected)`);
            } else {
                console.log(`  âœ— ${test.name}: FAIL (unexpected block)`);
            }
        }
    }
}

// Monitor container connections
async function monitorConnections() {
    console.log('\nðŸ“Š Monitoring active connections...\n');
    
    for (const container of CONTAINERS) {
        try {
            const cmd = `docker exec ${container.name} netstat -tn 2>/dev/null || echo "netstat not available"`;
            const { stdout } = await execPromise(cmd);
            
            if (!stdout.includes('not available')) {
                const connections = stdout.split('\n').filter(line => line.includes('ESTABLISHED'));
                
                connections.forEach(conn => {
                    const parts = conn.trim().split(/\s+/);
                    if (parts.length >= 4) {
                        logTraffic(container.name, parts[4], 'TCP', parts[3].split(':')[1] || 'unknown', 'ESTABLISHED');
                    }
                });
                
                console.log(`  ${container.name}: ${connections.length} active connections`);
            }
        } catch (error) {
            // Container might not have netstat, skip
        }
    }
}

// Generate daily summary
function generateDailySummary() {
    const timestamp = new Date().toISOString();
    const summary = `
${'='.repeat(80)}
Daily Network Summary - ${timestamp}
${'='.repeat(80)}

Network Configuration:
  - Backend Network (172.20.0.0/24): Database, Backend API, Encryption
  - Frontend Network (172.21.0.0/24): Frontend, IAM, Backend API (bridge)

Containers Monitored:
${CONTAINERS.map(c => `  - ${c.name} (${c.network}): ${c.ip}`).join('\n')}

Log Files:
  - Traffic Log: ${LOG_FILES.traffic}
  - Security Log: ${LOG_FILES.security}
  - Access Log: ${LOG_FILES.access}
  - Isolation Log: ${LOG_FILES.isolation}

${'='.repeat(80)}
`;
    
    writeLog(LOG_FILES.summary, summary);
    console.log(summary);
}

// Main monitoring loop
async function startMonitoring() {
    console.log('\nðŸš€ Starting Network Software-Defined Perimeter (SDP) Monitor\n');
    
    initializeLogs();
    generateDailySummary();
    
    // Run initial isolation tests
    await testNetworkIsolation();
    
    // Monitor connections
    await monitorConnections();
    
    // Log startup complete
    logSecurityEvent('MONITOR_START', 'INFO', 'Network monitoring started successfully', {
        containers: CONTAINERS.length,
        logDir: LOG_DIR
    });
    
    console.log('\nâœ“ Monitoring complete. Check log files for details.\n');
}

// Run monitoring
startMonitoring().catch(error => {
    console.error('Error during monitoring:', error);
    logSecurityEvent('MONITOR_ERROR', 'ERROR', 'Monitoring error', { error: error.message });
});


