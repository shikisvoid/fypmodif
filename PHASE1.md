
STEP 0 â€” Pre-Flight: Verify All Containers Are Running & Clean Old Alerts# Verify all 18 containers are up
docker ps --format "table {{.Names}}\t{{.Status}}"

# Clean old alerts & isolations so you start fresh
docker exec hospital-response-controller sh -c "echo '' > /logs/security-alerts.log; echo '' > /logs/role-violations.log; echo '[]' > /logs/isolations.json"

# Restart the monitor so it has a clean telemetry buffer
docker restart hospital-monitor
Start-Sleep -Seconds 10
echo "Monitor restarted â€” clean slate."


STEP 1 â€” Verify EDR Agents Are Alive (Telemetry Flowing)
# Check that EDR agents are sending telemetry to the monitor
docker logs --tail 5 edr-admin-workstation
docker logs --tail 5 edr-doctor-workstation
docker logs --tail 5 edr-accountant-workstation

ðŸ”¥ ATTACK 1 â€” Data Exfiltration (Rule 1)
What it does: An accountant's workstation makes an outbound connection to a known suspicious IP (8.8.8.8). The EDR agent detects this via netstat/ps aux, the traffic-analyzer fires Rule 1 EXFILTRATION_DETECTED, and the Response Controller isolates the host + revokes the accountant's tokens via IAM.

Severity: CRITICAL â†’ Host Isolation + Token Revocation

echo "===== ATTACK 1: DATA EXFILTRATION ====="
echo "Accountant workstation connecting to suspicious IP 8.8.8.8..."
docker exec -d edr-accountant-workstation sh -c "ping 8.8.8.8 -c 15 > /dev/null 2>&1"

# Wait for the EDR agent to pick it up (agent polls every 3s, monitor polls every 2s)
Start-Sleep -Seconds 12

echo "--- EDR Agent Detection ---"
docker logs --tail 10 edr-accountant-workstation 2>&1 | Select-String "SUSPICIOUS|suspicious|8.8.8"

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "EXFIL" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "EXFIL|isolat|revok" | Select-Object -Last 5
docker exec hospital-response-controller sh -c "tail -5 /logs/security-alerts.log"

ðŸ”¥ ATTACK 2 â€” Ransomware File Creation (Rule 3)
What it does: The doctor's workstation creates files with suspicious extensions (.encrypted, .lock, .ransom) in /tmp. The EDR agent's file monitor flags them as SUSPICIOUS_FILE, the traffic-analyzer fires Rule 3 RANSOMWARE_INDICATOR, and the Response Controller isolates the host + revokes the doctor's tokens.

Severity: CRITICAL â†’ Host Isolation + Token Revocation
echo "===== ATTACK 2: RANSOMWARE FILE CREATION ====="
echo "Creating suspicious encrypted files on doctor workstation..."
docker exec edr-doctor-workstation sh -c "echo ENCRYPTED_DATA > /tmp/patient_records.encrypted; echo LOCKED > /tmp/database.lock; echo RANSOM_NOTE > /tmp/readme.ransom; echo CRYPTO > /tmp/financials.crypto; echo LOCKED > /tmp/backup.locked"

# Wait for agent file scan cycle
Start-Sleep -Seconds 10

echo "--- EDR Agent Detection ---"
docker logs --tail 15 edr-doctor-workstation 2>&1 | Select-String "SUSPICIOUS|encrypted|ransom|lock"

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "RANSOM" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "RANSOM|isolat|revok" | Select-Object -Last 5
docker exec hospital-response-controller sh -c "tail -5 /logs/security-alerts.log"

ðŸ”¥ ATTACK 3 â€” Brute Force SSH Attack (Rule 4)
What it does: The admin workstation has 7 failed SSH authentication attempts logged in /var/log/auth.log. The EDR agent reads these logs and flags them as SECURITY_EVENT. The traffic-analyzer's Rule 4 counts 5+ auth failures within 15 minutes and fires BRUTE_FORCE_ATTEMPT. The Response Controller revokes tokens + blocks the IP.

Severity: HIGH â†’ Token Revocation + IP Block

echo "===== ATTACK 3: BRUTE FORCE SSH ATTACK ====="
echo "Injecting 7 failed auth attempts into admin workstation logs..."
docker exec edr-admin-workstation sh -c "mkdir -p /var/log && for i in 1 2 3 4 5 6 7; do echo \"\$(date '+%b %d %H:%M:%S') admin-workstation sshd[999]: Failed password for admin from 10.0.0.55 port 22\" >> /var/log/auth.log; done && echo 'Injected 7 auth failure lines' && tail -3 /var/log/auth.log"

# Wait for agent log scan cycle
Start-Sleep -Seconds 10

echo "--- EDR Agent Detection ---"
docker logs --tail 10 edr-admin-workstation 2>&1 | Select-String "SECURITY_EVENT|auth|fail"

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "BRUTE" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "BRUTE|revok|block" | Select-Object -Last 5
docker exec hospital-response-controller sh -c "tail -5 /logs/security-alerts.log"

ðŸ”¥ ATTACK 4 â€” Role-Based Access Violation (Rule 2)
What it does: The accountant's role tries to access /api/labs/dashboard â€” an endpoint not in the accountant's allowed list. The EDR middleware on the backend server detects this as a ROLE_ACCESS_VIOLATION, sends an immediate telemetry alert, the traffic-analyzer fires Rule 2, and the Response Controller revokes the accountant's tokens.

Severity: HIGH â†’ Token Revocation

echo "===== ATTACK 4: ROLE ACCESS VIOLATION ====="
echo "Injecting role violation: accountant accessing /api/labs/dashboard..."

# Method 1: Inject directly into the telemetry pipeline (simulates what the EDR middleware would send)
docker exec hospital-monitor node -e "const http=require('http');const d=JSON.stringify({hostId:'hospital-backend',ts:new Date().toISOString(),source:'edr-middleware',eventType:'ROLE_ACCESS_VIOLATION',security:{userEmail:'accountant@hospital.com',userRole:'accountant',method:'GET',path:'/api/labs/dashboard',statusCode:403,ip:'172.21.0.156'}});const r=http.request({hostname:'127.0.0.1',port:9090,path:'/ingest/telemetry',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(d)}},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>console.log('Injected:',b))});r.write(d);r.end();"

Start-Sleep -Seconds 8

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "ROLE_ACCESS" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "ROLE|violat|revok" | Select-Object -Last 5
docker exec hospital-response-controller sh -c "tail -10 /logs/role-violations.log"

# Patient tries to access admin panel
docker exec hospital-monitor node -e "const http=require('http');const d=JSON.stringify({hostId:'hospital-backend',ts:new Date().toISOString(),source:'edr-middleware',eventType:'ROLE_ACCESS_VIOLATION',security:{userEmail:'patient@hospital.com',userRole:'patient',method:'GET',path:'/api/admin/dashboard',statusCode:403,ip:'172.21.0.157'}});const r=http.request({hostname:'127.0.0.1',port:9090,path:'/ingest/telemetry',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(d)}},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>console.log('Injected:',b))});r.write(d);r.end();"

# Nurse tries to access pharmacy
docker exec hospital-monitor node -e "const http=require('http');const d=JSON.stringify({hostId:'hospital-backend',ts:new Date().toISOString(),source:'edr-middleware',eventType:'ROLE_ACCESS_VIOLATION',security:{userEmail:'nurse@hospital.com',userRole:'nurse',method:'GET',path:'/api/pharmacy/inventory',statusCode:403,ip:'172.21.0.152'}});const r=http.request({hostname:'127.0.0.1',port:9090,path:'/ingest/telemetry',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(d)}},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>console.log('Injected:',b))});r.write(d);r.end();"

# Pharmacist tries to access billing
docker exec hospital-monitor node -e "const http=require('http');const d=JSON.stringify({hostId:'hospital-backend',ts:new Date().toISOString(),source:'edr-middleware',eventType:'ROLE_ACCESS_VIOLATION',security:{userEmail:'pharmacist@hospital.com',userRole:'pharmacist',method:'POST',path:'/api/billing/create',statusCode:403,ip:'172.20.0.155'}});const r=http.request({hostname:'127.0.0.1',port:9090,path:'/ingest/telemetry',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(d)}},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>console.log('Injected:',b))});r.write(d);r.end();"

Start-Sleep -Seconds 8
echo "--- All Role Violations Logged ---"
docker exec hospital-response-controller sh -c "cat /logs/role-violations.log"

ðŸ”¥ ATTACK 5a â€” Database: Unauthorized Table Access (Rule 5)
What it does: The accountant user accesses lab_tests and lab_results tables â€” tables NOT in the accountant's ROLE_TABLE_POLICY. The db-monitor in the accountant's EDR agent detects this by scanning audit_logs and fires DB_UNAUTHORIZED_TABLE_ACCESS.

Severity: HIGH â†’ Token Revocation

echo "===== ATTACK 5a: DB UNAUTHORIZED TABLE ACCESS ====="
echo "Accountant snooping lab_tests and lab_results tables..."
docker exec hospital-db psql -U hospital -d hospital_db -c "
DO \$\$
DECLARE acct_id uuid;
BEGIN
  SELECT id INTO acct_id FROM users WHERE email = 'accountant@hospital.com';
  INSERT INTO audit_logs (actor_id, action, resource_type, status, details) VALUES
    (acct_id, 'READ', 'lab_tests', 'success', '{\"reason\":\"accountant snooping lab results\"}'),
    (acct_id, 'READ', 'lab_tests', 'success', '{\"reason\":\"accountant snooping lab results\"}'),
    (acct_id, 'READ', 'lab_results', 'success', '{\"reason\":\"accountant accessing lab results\"}'),
    (acct_id, 'UPDATE', 'lab_tests', 'success', '{\"reason\":\"accountant modifying lab data\"}');
  RAISE NOTICE 'Injected 4 unauthorized table access entries';
END \$\$;
"

Start-Sleep -Seconds 10

echo "--- EDR Agent (Accountant) DB Detection ---"
docker logs --tail 15 edr-accountant-workstation 2>&1 | Select-String "DB_UNAUTH|DB alert|lab_tests"

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "DB_UNAUTHORIZED" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "DB_UNAUTH|Database alert|revok" | Select-Object -Last 5


 ATTACK 5b â€” Database: Mass Delete Attack (Rule 5)
What it does: 7 DELETE entries on the patients table appear in audit_logs (threshold is 5). The db-monitor fires DB_MASS_DELETE. Response: host isolation + token revocation.

Severity: CRITICAL â†’ Host Isolation + Token Revocation
echo "===== ATTACK 5b: DB MASS DELETE ====="
echo "Accountant mass-deleting patient records..."
docker exec hospital-db psql -U hospital -d hospital_db -c "
DO \$\$
DECLARE acct_id uuid;
BEGIN
  SELECT id INTO acct_id FROM users WHERE email = 'accountant@hospital.com';
  INSERT INTO audit_logs (actor_id, action, resource_type, status, details) VALUES
    (acct_id, 'DELETE', 'patients', 'success', '{\"bulk_delete\":true,\"record\":1}'),
    (acct_id, 'DELETE', 'patients', 'success', '{\"bulk_delete\":true,\"record\":2}'),
    (acct_id, 'DELETE', 'patients', 'success', '{\"bulk_delete\":true,\"record\":3}'),
    (acct_id, 'DELETE', 'patients', 'success', '{\"bulk_delete\":true,\"record\":4}'),
    (acct_id, 'DELETE', 'patients', 'success', '{\"bulk_delete\":true,\"record\":5}'),
    (acct_id, 'DELETE', 'patients', 'success', '{\"bulk_delete\":true,\"record\":6}'),
    (acct_id, 'DELETE', 'patients', 'success', '{\"bulk_delete\":true,\"record\":7}');
  RAISE NOTICE 'Injected 7 mass delete entries on patients table';
END \$\$;
"

Start-Sleep -Seconds 10

echo "--- EDR Agent (Accountant) DB Detection ---"
docker logs --tail 15 edr-accountant-workstation 2>&1 | Select-String "DB_MASS|mass|delete|DB alert"

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "DB_MASS_DELETE" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "DB_MASS|isolat|revok" | Select-Object -Last 5

ATTACK 5c â€” Database: Bulk Data Exfiltration (Rule 5)
What it does: 26 READ/EXPORT entries on the patients table appear in audit_logs (threshold is 20). The db-monitor fires DB_BULK_DATA_READ. Response: token revocation.

Severity: HIGH â†’ Token Revocation

echo "===== ATTACK 5c: DB BULK DATA EXFILTRATION ====="
echo "Accountant bulk-reading/exporting patient records..."
docker exec hospital-db psql -U hospital -d hospital_db -c "
DO \$\$
DECLARE acct_id uuid;
BEGIN
  SELECT id INTO acct_id FROM users WHERE email = 'accountant@hospital.com';
  INSERT INTO audit_logs (actor_id, action, resource_type, status, details) VALUES
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":1}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":2}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":3}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":4}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":5}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":6}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":7}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":8}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":9}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":10}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":11}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":12}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":13}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":14}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":15}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":16}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":17}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":18}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":19}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":20}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":21}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":22}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":23}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":24}'),
    (acct_id, 'READ', 'patients', 'success', '{\"export_attempt\":true,\"page\":25}'),
    (acct_id, 'EXPORT', 'patients', 'success', '{\"full_export\":true}');
  RAISE NOTICE 'Injected 26 bulk read entries on patients table';
END \$\$;
"

Start-Sleep -Seconds 10

echo "--- EDR Agent (Accountant) DB Detection ---"
docker logs --tail 15 edr-accountant-workstation 2>&1 | Select-String "DB_BULK|bulk|read|DB alert"

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "DB_BULK" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "DB_BULK|revok" | Select-Object -Last 5


 ATTACK 6 â€” Exfiltration from MULTIPLE Roles (Multi-Host)
What it does: Suspicious outbound connections from 3 different role workstations simultaneously â€” shows the EDR monitors ALL 8 endpoints independently.

Severity: CRITICAL Ã— 3 â†’ Each host isolated + tokens revoked

echo "===== ATTACK 6: MULTI-HOST EXFILTRATION ====="
echo "Launching suspicious connections from doctor, nurse, and patient endpoints..."

# Doctor connects to known Tor exit node
docker exec -d edr-doctor-workstation sh -c "ping 185.220.101.1 -c 10 > /dev/null 2>&1"

# Nurse connects to 1.1.1.1 (flagged as suspicious in EDR config)
docker exec -d edr-nurse-workstation sh -c "ping 1.1.1.1 -c 10 > /dev/null 2>&1"

# Patient connects to 8.8.8.8
docker exec -d edr-patient-terminal sh -c "ping 8.8.8.8 -c 10 > /dev/null 2>&1"

Start-Sleep -Seconds 15

echo "--- Monitor Exfiltration Alerts ---"
docker logs hospital-monitor 2>&1 | Select-String "EXFIL" | Select-Object -Last 10

echo "--- Response Controller Actions ---"
docker logs hospital-response-controller 2>&1 | Select-String "EXFIL|isolat|revok" | Select-Object -Last 10

 ATTACK 7 â€” Ransomware Spreading to Multiple Hosts
What it does: Ransomware files appear on multiple workstations simultaneously â€” simulates a worm/lateral movement scenario.

Severity: CRITICAL Ã— 2 â†’ Each host isolated
echo "===== ATTACK 7: RANSOMWARE SPREADING ====="

# Nurse workstation gets hit
docker exec edr-nurse-workstation sh -c "echo ENCRYPTED > /tmp/medical_records.encrypted; echo LOCKED > /tmp/system.lock"

# Receptionist workstation gets hit
docker exec edr-receptionist-workstation sh -c "echo RANSOM > /tmp/all_appointments.ransom; echo CRYPTO > /tmp/billing_data.crypto"

Start-Sleep -Seconds 12

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "RANSOM" | Select-Object -Last 10

echo "--- Response Controller Actions ---"
docker logs hospital-response-controller 2>&1 | Select-String "RANSOM|isolat|revok" | Select-Object -Last 10


ðŸ”¥ ATTACK 8 â€” Brute Force from Pharmacist Workstation
What it does: Multiple authentication failures from the pharmacist workstation â€” could be an attacker trying to escalate privileges.

Severity: HIGH â†’ Token Revocation + IP Block
echo "===== ATTACK 8: BRUTE FORCE FROM PHARMACIST ====="
docker exec edr-pharmacist-workstation sh -c "mkdir -p /var/log && for i in 1 2 3 4 5 6; do echo \"\$(date '+%b %d %H:%M:%S') pharmacist-workstation sshd[1234]: Failed password for root from 192.168.1.100 port 22\" >> /var/log/auth.log; done && echo 'Injected 6 auth failures'"

Start-Sleep -Seconds 10

echo "--- Monitor Detection ---"
docker logs hospital-monitor 2>&1 | Select-String "BRUTE" | Select-Object -Last 5

echo "--- Response Controller Action ---"
docker logs hospital-response-controller 2>&1 | Select-String "BRUTE|revok|block" | Select-Object -Last 5

ATTACK 9 â€” Combined Attack (All 5 Rules at Once â€” Using the SQL Script)
What it does: Fires ALL database rules simultaneously using the pre-built SQL injection script, combined with host-based attacks.

echo "===== ATTACK 9: COMBINED ALL-RULES ATTACK ====="

# 1. Exfiltration from lab technician
docker exec -d edr-labtech-workstation sh -c "ping 8.8.8.8 -c 10 > /dev/null 2>&1"

# 2. Ransomware on pharmacist
docker exec edr-pharmacist-workstation sh -c "echo ENCRYPTED > /tmp/drug_inventory.encrypted; echo LOCKED > /tmp/prescriptions.lock"

# 3. Brute force on receptionist
docker exec edr-receptionist-workstation sh -c "mkdir -p /var/log && for i in 1 2 3 4 5 6 7 8; do echo \"\$(date '+%b %d %H:%M:%S') receptionist sshd[555]: Failed password for admin from 10.10.10.99 port 22\" >> /var/log/auth.log; done"

# 4. All DB rules via the demo-inject.sql script
docker cp demo-inject.sql hospital-db:/tmp/demo-inject.sql
docker exec hospital-db psql -U hospital -d hospital_db -f /tmp/demo-inject.sql

# 5. Role violation: patient accessing admin API
docker exec hospital-monitor node -e "const http=require('http');const d=JSON.stringify({hostId:'hospital-backend',ts:new Date().toISOString(),source:'edr-middleware',eventType:'ROLE_ACCESS_VIOLATION',security:{userEmail:'patient@hospital.com',userRole:'patient',method:'DELETE',path:'/api/admin/users/1',statusCode:403,ip:'172.21.0.157'}});const r=http.request({hostname:'127.0.0.1',port:9090,path:'/ingest/telemetry',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(d)}},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>console.log('Injected:',b))});r.write(d);r.end();"

echo "Waiting for all detections to propagate..."
Start-Sleep -Seconds 15


STEP FINAL â€” View All Detections & Response Actions
echo "============================================================"
echo "           COMPLETE EDR DETECTION SUMMARY"
echo "============================================================"

echo ""
echo "===== 1. SECURITY ALERTS LOG (Monitor) ====="
docker exec hospital-monitor sh -c "tail -40 /logs/security-alerts.log"

echo ""
echo "===== 2. RESPONSE CONTROLLER ALERTS LOG ====="
docker exec hospital-response-controller sh -c "tail -40 /logs/security-alerts.log"

echo ""
echo "===== 3. ROLE VIOLATIONS LOG ====="
docker exec hospital-response-controller sh -c "cat /logs/role-violations.log"

echo ""
echo "===== 4. ALL ISOLATIONS & RESPONSE ACTIONS ====="
docker exec hospital-response-controller sh -c "cat /logs/isolations.json" | ConvertFrom-Json | Format-Table -AutoSize

echo ""
echo "===== 5. EDR AGENT LOGS (sample from each role) ====="
echo "--- Admin ---"
docker logs --tail 3 edr-admin-workstation 2>&1 | Select-String "alert|SUSPICIOUS|DB"
echo "--- Doctor ---"
docker logs --tail 3 edr-doctor-workstation 2>&1 | Select-String "alert|SUSPICIOUS|DB"
echo "--- Accountant ---"
docker logs --tail 3 edr-accountant-workstation 2>&1 | Select-String "alert|SUSPICIOUS|DB"

echo ""
echo "============================================================"
echo "           NETWORK SDP TEST"
echo "============================================================"
echo "Running SDP verification..."
docker exec hospital-monitor sh -c "tail -30 /logs/traffic-analysis.log"


echo "===== CLEANING UP ====="

# Remove ransomware files from all containers
docker exec edr-doctor-workstation sh -c "rm -f /tmp/*.encrypted /tmp/*.lock /tmp/*.ransom /tmp/*.crypto /tmp/*.locked" 2>$null
docker exec edr-nurse-workstation sh -c "rm -f /tmp/*.encrypted /tmp/*.lock /tmp/*.ransom /tmp/*.crypto" 2>$null
docker exec edr-receptionist-workstation sh -c "rm -f /tmp/*.ransom /tmp/*.crypto" 2>$null
docker exec edr-pharmacist-workstation sh -c "rm -f /tmp/*.encrypted /tmp/*.lock" 2>$null

# Clear auth.log brute force entries
docker exec edr-admin-workstation sh -c "echo '' > /var/log/auth.log" 2>$null
docker exec edr-pharmacist-workstation sh -c "echo '' > /var/log/auth.log" 2>$null
docker exec edr-receptionist-workstation sh -c "echo '' > /var/log/auth.log" 2>$null

# Clean response controller logs and isolations
docker exec hospital-response-controller sh -c "echo '' > /logs/security-alerts.log; echo '' > /logs/role-violations.log; echo '[]' > /logs/isolations.json"

# Restart monitor for clean telemetry buffer
docker restart hospital-monitor

echo "Cleanup complete. System ready for next demo."

