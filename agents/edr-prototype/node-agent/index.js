// Simple EDR prototype agent (simulated telemetry)
const http = require('http');
const { URL } = require('url');

const TARGET = process.env.TARGET || 'http://localhost:9090/ingest/telemetry';
const HOST_ID = process.env.HOST_ID || `host-${Math.random().toString(16).slice(2,8)}`;
const INTERVAL = parseInt(process.env.INTERVAL_MS || '1000', 10);

function randomPid() { return Math.floor(100 + Math.random() * 20000); }
function randomProcess() {
  const procs = ['svchost', 'node', 'python', 'cmd', 'bash', 'mysql', 'postgres', 'nginx'];
  const p = procs[Math.floor(Math.random() * procs.length)];
  return { name: p, pid: randomPid(), cmd: `${p} --example` };
}

function randomNetworkEvent() {
  const ips = ['10.0.0.5','10.0.0.6','10.0.1.4','172.18.0.3','8.8.8.8'];
  return { src: '127.0.0.1', dst: ips[Math.floor(Math.random()*ips.length)], port: Math.floor(1024 + Math.random()*48000) };
}

function sendTelemetry(event) {
  const url = new URL(TARGET);
  const payload = JSON.stringify(event);
  const options = {
    hostname: url.hostname,
    port: url.port || 80,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  };

  const req = http.request(options, (res) => {
    // ignore response body
    res.on('data', () => {});
  });

  req.on('error', (err) => {
    console.error(`Failed to send telemetry: ${err.message}`);
  });

  req.write(payload);
  req.end();
}

console.log(`EDR prototype agent starting. HOST_ID=${HOST_ID} -> ${TARGET}`);

setInterval(() => {
  const p = randomProcess();
  const evt = {
    hostId: HOST_ID,
    ts: new Date().toISOString(),
    type: 'process_start',
    process: p,
    net: randomNetworkEvent()
  };
  console.log('sending telemetry', evt);
  sendTelemetry(evt);
}, INTERVAL);
