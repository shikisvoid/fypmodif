const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');

const PORT = parseInt(process.env.PORT || '7000', 10);
const POLICY_FILE = process.env.SDP_POLICY_FILE || path.join(__dirname, 'policy.json');

const DEFAULT_POLICY = {
  version: 'builtin-default',
  adminBypass: true,
  defaultDecision: 'allow',
  publicPaths: [
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
  ],
  pathRules: [
    { prefix: '/api/monitoring', requiredPermission: 'canViewReports', allowedRoles: ['admin'] },
    { prefix: '/api/admin', requiredPermission: 'canManageUsers', allowedRoles: ['admin'] },
    { prefix: '/api/lab', requiredPermission: 'canViewLabs', allowedRoles: ['admin', 'doctor', 'lab_technician'] },
    { prefix: '/api/pharmacy', requiredPermission: 'canViewPharmacy', allowedRoles: ['admin', 'doctor', 'pharmacist', 'nurse'] },
    { prefix: '/api/billing', requiredPermission: 'canViewBilling', allowedRoles: ['admin', 'accountant'] },
    { prefix: '/api/files', requiredPermission: 'canViewPatientFiles', allowedRoles: ['admin', 'doctor', 'nurse'] }
  ]
};

let activePolicy = DEFAULT_POLICY;
let activePolicySource = 'builtin';
let activePolicyMtimeMs = 0;
let activePolicyLoadedAt = new Date().toISOString();

function startsWithAny(pathname, prefixes) {
  return prefixes.some((prefix) => pathname === prefix || pathname.startsWith(prefix + '/'));
}

function normalizePolicy(raw) {
  const policy = raw && typeof raw === 'object' ? raw : {};
  const merged = {
    version: typeof policy.version === 'string' ? policy.version : DEFAULT_POLICY.version,
    adminBypass: typeof policy.adminBypass === 'boolean' ? policy.adminBypass : DEFAULT_POLICY.adminBypass,
    defaultDecision: policy.defaultDecision === 'deny' ? 'deny' : 'allow',
    publicPaths: Array.isArray(policy.publicPaths) ? policy.publicPaths.filter((v) => typeof v === 'string') : DEFAULT_POLICY.publicPaths,
    pathRules: Array.isArray(policy.pathRules) ? policy.pathRules : DEFAULT_POLICY.pathRules
  };

  merged.pathRules = merged.pathRules
    .filter((rule) => rule && typeof rule === 'object' && typeof rule.prefix === 'string')
    .map((rule) => ({
      prefix: rule.prefix,
      requiredPermission: typeof rule.requiredPermission === 'string' ? rule.requiredPermission : null,
      allowedRoles: Array.isArray(rule.allowedRoles) ? rule.allowedRoles.filter((r) => typeof r === 'string') : null
    }));

  return merged;
}

function loadPolicyFromDisk() {
  const raw = fs.readFileSync(POLICY_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  const stat = fs.statSync(POLICY_FILE);
  activePolicy = normalizePolicy(parsed);
  activePolicySource = POLICY_FILE;
  activePolicyMtimeMs = stat.mtimeMs;
  activePolicyLoadedAt = new Date().toISOString();
}

function refreshPolicyIfChanged() {
  try {
    const stat = fs.statSync(POLICY_FILE);
    if (stat.mtimeMs !== activePolicyMtimeMs || activePolicySource === 'builtin') {
      loadPolicyFromDisk();
      console.log(`[SDP] Policy loaded from ${POLICY_FILE} (version=${activePolicy.version})`);
    }
  } catch (err) {
    if (activePolicySource !== 'builtin') {
      console.error(`[SDP] Policy reload failed, continuing with previous in-memory policy: ${err.message}`);
    } else {
      console.error(`[SDP] Policy file unavailable (${POLICY_FILE}), using built-in defaults: ${err.message}`);
    }
  }
}

function resolveRule(pathname) {
  return activePolicy.pathRules.find((rule) => pathname === rule.prefix || pathname.startsWith(rule.prefix + '/')) || null;
}

function evaluateRule(pathname, method, identity) {
  if (startsWithAny(pathname, activePolicy.publicPaths)) {
    return { allow: true, reason: 'public_path' };
  }

  if (!identity || !identity.email) {
    return { allow: false, reason: 'missing_identity' };
  }

  if (activePolicy.adminBypass && identity.role === 'admin') {
    return { allow: true, reason: 'admin_bypass' };
  }

  const rule = resolveRule(pathname);
  if (!rule) {
    return {
      allow: activePolicy.defaultDecision === 'allow',
      reason: activePolicy.defaultDecision === 'allow' ? 'default_allow' : 'default_deny'
    };
  }

  let permissionDecision = null;
  if (rule.requiredPermission) {
    const permissions = identity.permissions;
    if (permissions && typeof permissions === 'object' && Object.prototype.hasOwnProperty.call(permissions, rule.requiredPermission)) {
      permissionDecision = Boolean(permissions[rule.requiredPermission]);
    }
  }

  let roleDecision = null;
  if (rule.allowedRoles && rule.allowedRoles.length > 0) {
    roleDecision = rule.allowedRoles.includes(identity.role);
  }

  if (permissionDecision === false || roleDecision === false) {
    return {
      allow: false,
      reason: permissionDecision === false ? 'permission_denied' : 'role_denied',
      meta: {
        pathname,
        method: method || 'GET',
        role: identity.role || 'unknown',
        rule: rule.prefix
      }
    };
  }

  if (permissionDecision === true || roleDecision === true) {
    return {
      allow: true,
      reason: permissionDecision === true ? 'policy_allow_permission' : 'policy_allow_role',
      meta: {
        pathname,
        method: method || 'GET',
        role: identity.role || 'unknown',
        rule: rule.prefix
      }
    };
  }

  return {
    allow: false,
    reason: 'insufficient_identity_context',
    meta: {
      pathname,
      method: method || 'GET',
      role: identity.role || 'unknown',
      rule: rule.prefix
    }
  };
}

const app = express();
app.use(helmet());
app.use(express.json({ limit: '256kb' }));

app.get('/health', (req, res) => {
  refreshPolicyIfChanged();
  res.json({
    ok: true,
    service: 'sdp-controller',
    policy: {
      source: activePolicySource,
      version: activePolicy.version,
      loadedAt: activePolicyLoadedAt
    },
    ts: new Date().toISOString()
  });
});

app.post('/authorize', (req, res) => {
  refreshPolicyIfChanged();
  const { pathname, method, identity, enforcement } = req.body || {};

  if (!enforcement) {
    return res.json({ allow: true, reason: 'enforcement_disabled', policyVersion: activePolicy.version });
  }

  if (!pathname || typeof pathname !== 'string') {
    return res.status(400).json({ allow: false, reason: 'invalid_pathname', policyVersion: activePolicy.version });
  }

  const decision = evaluateRule(pathname, method, identity);
  return res.json({
    ...decision,
    policyVersion: activePolicy.version
  });
});

app.listen(PORT, '0.0.0.0', () => {
  refreshPolicyIfChanged();
  console.log(`[SDP] Controller listening on http://0.0.0.0:${PORT}`);
  console.log(`[SDP] Active policy source: ${activePolicySource} (version=${activePolicy.version})`);
});
