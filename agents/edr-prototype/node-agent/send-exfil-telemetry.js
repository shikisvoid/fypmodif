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
