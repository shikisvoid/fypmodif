TEST1 : STARTING THE EDR AGENT 
cd agents/edr-prototype/node-agent
npm install
$env:TARGET="http://localhost:9090/ingest/telemetry"
$env:HOST_ID="test-endpoint-1"
$env:INTERVAL_MS="2000"
node index.js
```
**Verification:**
```powershell
# Check telemetry endpoint
curl.exe http://localhost:9090/telemetry


 Test 2: SDP Identity-Aware Access Enforcement

**Objective:** Verify network isolation is working correctly

```powershell
# Test 1: Frontend CANNOT access database (should FAIL)
# Unauthenticated call should be denied by SDP
# Expected: 401 SDP denied

# Test 2: Backend CAN access database (should SUCCEED)
# Health check for gateway
# Expected: SDP gateway status JSON

# Test 3: Frontend CAN access backend (should SUCCEED)
curl http://localhost:8088/api/patients
# Expected: SDP gateway status JSON

# Test 4: IAM CANNOT access database (should FAIL)
curl http://localhost:8088/health
# Expected: 401 SDP denied

# Test 5: Frontend CANNOT access encryption service (should FAIL)
# Access to backend APIs now mediated by gateway policy
# Expected: 401 SDP denied


Test 3: Rule-Based Detection System
Get-Content "PHASE1\docker-volumes\monitor-logs\comprehensive-network-monitor.log" -Tail 50 

Test 4: Alert Generation & Response Controller
cd "PHASE1\PHASE1\HealthCareCenter\response\controller"
npm install
$env:PORT="4100"
node index.js

Response Controller running on http://localhost:4100

SENDING A NON CRITICAL ALERT
  Invoke-WebRequest -Uri "http://localhost:4100/alert" -Method POST -ContentType "application/json" -UseBasicParsing -Body '{
  "severity": "WARNING",
  "event": "UNEXPECTED_BLOCK",
  "hostId": "test-host-1",
  "ts": "2026-01-30T12:00:00Z",
  "details": { "source": "hospital-frontend", "target": "172.21.0.20" } }'


SENDING A CRITICAL ALERT
# Send CRITICAL alert (simulates exfiltration attempt)
  Invoke-WebRequest -Uri "http://localhost:4100/alert" -Method POST -ContentType "application/json" -UseBasicParsing -Body '{
  "severity": "CRITICAL",
  "event": "EXFILTRATION",
  "hostId": "test-host-2",
  "ts": "2026-01-30T12:05:00Z",
  "details": { "dst": "8.8.8.8", "port": 443 }
}'

ISOLATION HISTORY
# Get all isolation actions
 Invoke-WebRequest -Uri "http://localhost:4100/isolations" -UseBasicParsing
```

```powershell
# Revert isolation for a host
Invoke-WebRequest -Uri "http://localhost:4100/action/revert" -Method POST -ContentType "application/json" -UseBasicParsing -Body '{"hostId":"test-host-2"}'


```powershell
# Modify EDR agent to send suspicious telemetry
cd agents/edr-prototype/node-agent

# Create a test script that sends exfiltration telemetry
@"
const http = require('http');

const telemetry = {
  hostId: 'compromised-endpoint',
  ts: new Date().toISOString(),
  type: 'network_connection',
  process: { name: 'suspicious.exe', pid: 1234, cmd: 'suspicious.exe --exfil' },
  net: { src: '172.20.0.20', dst: '8.8.8.8', port: 443 }
};

const data = JSON.stringify(telemetry);
const options = {
  hostname: 'localhost',
  port: 9090,
  path: '/ingest/telemetry',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data)
  }
};

const req = http.request(options, (res) => {
  console.log('Telemetry sent, status:', res.statusCode);
});

req.on('error', (err) => console.error('Error:', err.message));
req.write(data);
req.end();
"@ | Out-File -FilePath send-exfil-telemetry.js -Encoding utf8

node send-exfil-telemetry.js
```

# Check controller received alert
curl http://localhost:4100/isolations

