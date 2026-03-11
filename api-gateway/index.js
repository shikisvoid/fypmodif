const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const http = require('http');
const https = require('https');

const PORT = parseInt(process.env.PORT || '8080', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'sdp_phase2_shared_secret_change_me';
const IAM_URL = process.env.IAM_URL || 'http://iam:4000';
const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:3000';
const SDP_CONTROLLER_URL = process.env.SDP_CONTROLLER_URL || 'http://sdp-controller:7000';
const SDP_ENFORCEMENT = process.env.SDP_ENFORCEMENT !== 'false';
const SDP_FAIL_OPEN = process.env.SDP_FAIL_OPEN === 'true';

const PUBLIC_PATHS = [
  '/api/login',
  '/api/mfa',
  '/api/token',
  '/api/logout',
  '/api/me',
  '/api/admin/mfa/secret',
  '/api/security/revoke-user',
  '/api/security/block-ip',
  '/api/health',
  '/api/monitoring/health'
];

const BACKEND_PREFIXES = [
  '/api/patients',
  '/api/appointments',
  '/api/vitals',
  '/api/prescriptions',
  '/api/lab',
  '/api/billing',
  '/api/pharmacy',
  '/api/files',
  '/api/audit',
  '/api/monitoring',
  '/api/dashboard',
  '/api/doctor',
  '/api/receptionist',
  '/api/nurse',
  '/api/accountant',
  '/api/notifications',
  '/api/encryption',
  '/api/doctors',
  '/api/users'
];

function startsWithAny(pathname, prefixes) {
  return prefixes.some((prefix) => pathname === prefix || pathname.startsWith(prefix + '/'));
}

function isPublicPath(pathname) {
  return startsWithAny(pathname, PUBLIC_PATHS);
}

function isBackendPath(pathname) {
  return startsWithAny(pathname, BACKEND_PREFIXES);
}

function targetFor(pathname) {
  if (isBackendPath(pathname)) {
    return BACKEND_URL;
  }
  return IAM_URL;
}

function parseToken(req) {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

function postJson(urlString, payload) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;
    const body = JSON.stringify(payload);

    const req = client.request({
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: 3000
    }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(raw || '{}');
          resolve({ status: res.statusCode || 500, body: parsed });
        } catch (err) {
          reject(new Error('Invalid controller response JSON'));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Controller request timed out'));
    });

    req.on('error', (err) => reject(err));
    req.write(body);
    req.end();
  });
}

async function authorizeWithController({ pathname, method, identity, sourceIp }) {
  const result = await postJson(`${SDP_CONTROLLER_URL}/authorize`, {
    pathname,
    method,
    identity,
    sourceIp,
    enforcement: SDP_ENFORCEMENT
  });

  if (result.status >= 400) {
    throw new Error(`Controller error status ${result.status}`);
  }

  return result.body;
}

function createProxyRequest(req, res, targetBase) {
  const url = new URL(targetBase);
  const isHttps = url.protocol === 'https:';
  const requestClient = isHttps ? https : http;

  const options = {
    hostname: url.hostname,
    port: url.port || (isHttps ? 443 : 80),
    method: req.method,
    path: req.originalUrl,
    headers: {
      ...req.headers,
      host: url.host,
      'x-sdp-enforced': 'true'
    }
  };

  const proxyReq = requestClient.request(options, (proxyRes) => {
    res.status(proxyRes.statusCode || 502);
    Object.entries(proxyRes.headers || {}).forEach(([key, value]) => {
      if (value !== undefined) {
        res.setHeader(key, value);
      }
    });
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      res.status(502).json({ success: false, error: 'SDP gateway upstream error', details: err.message });
    }
  });

  req.pipe(proxyReq);
}

const app = express();

app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.get('/health', (req, res) => {
  // Keep the gateway health check self-contained so it does not hang on downstream auth checks.
  res.json({
    ok: true,
    service: 'sdp-gateway',
    enforcement: SDP_ENFORCEMENT,
    failOpen: SDP_FAIL_OPEN,
    controllerUrl: SDP_CONTROLLER_URL,
    ts: new Date().toISOString()
  });
});

app.use('/api', async (req, res, next) => {
  const pathname = req.originalUrl.split('?')[0];

  if (!SDP_ENFORCEMENT || isPublicPath(pathname)) {
    return next();
  }

  const token = parseToken(req);
  if (!token) {
    return res.status(401).json({ success: false, error: 'SDP denied: missing token' });
  }

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ success: false, error: 'SDP denied: invalid or expired token' });
  }

  try {
    const decision = await authorizeWithController({
      pathname,
      method: req.method,
      identity: payload,
      sourceIp: req.ip || req.connection.remoteAddress || 'unknown'
    });

    if (!decision.allow) {
      return res.status(403).json({ success: false, error: `SDP denied: ${decision.reason || 'policy_denied'}` });
    }

    req.sdpDecision = decision;
    req.sdpIdentity = payload;
    return next();
  } catch (err) {
    if (SDP_FAIL_OPEN) {
      req.sdpDecision = { allow: true, reason: 'controller_unreachable_fail_open' };
      req.sdpIdentity = payload;
      return next();
    }

    return res.status(503).json({
      success: false,
      error: 'SDP denied: controller unavailable',
      details: err.message
    });
  }
});

app.use('/api', (req, res) => {
  const target = targetFor(req.originalUrl.split('?')[0]);
  createProxyRequest(req, res, target);
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SDP] API Gateway listening on http://0.0.0.0:${PORT}`);
  console.log(`[SDP] IAM upstream: ${IAM_URL}`);
  console.log(`[SDP] Backend upstream: ${BACKEND_URL}`);
  console.log(`[SDP] Controller: ${SDP_CONTROLLER_URL}`);
  console.log(`[SDP] Enforcement: ${SDP_ENFORCEMENT ? 'enabled' : 'disabled'} | FailOpen: ${SDP_FAIL_OPEN}`);
});
