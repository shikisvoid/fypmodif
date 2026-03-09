const express = require('express')
const cors = require('cors')
const fs = require('fs')
const path = require('path')
const speakeasy = require('speakeasy')
const bodyParser = require('body-parser')
const crypto = require('crypto')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const rateLimit = require('express-rate-limit')
const helmet = require('helmet')
const http = require('http')
require('dotenv').config({ path: path.join(__dirname, '.env') })

console.log('Loading dependencies...')

// ===== PHASE 2 EDR ROLE-AWARE MIDDLEWARE =====
let createEdrMiddleware = null
try {
  const edrModule = require('/edr/role-edr-middleware')
  createEdrMiddleware = edrModule.createEdrMiddleware
  console.log('✓ EDR role-aware middleware loaded')
} catch (err) {
  console.warn('⚠ EDR role-aware middleware not available:', err.message)
}

// ===== PHASE 2 INTEGRATION CONFIG =====
const PHASE2_CONFIG = {
  TELEMETRY_HOST: process.env.TELEMETRY_HOST || '172.21.0.100',
  TELEMETRY_PORT: process.env.TELEMETRY_PORT || 9090,
  RESPONSE_CONTROLLER_HOST: process.env.RESPONSE_CONTROLLER_HOST || '172.21.0.130',
  RESPONSE_CONTROLLER_PORT: process.env.RESPONSE_CONTROLLER_PORT || 4100,
  HOST_ID: 'hospital-iam',
  ENABLED: process.env.PHASE2_INTEGRATION !== 'false'
}

// Track login failures for brute force detection
const loginFailureTracker = new Map() // IP -> { count, firstFailure }
const BRUTE_FORCE_THRESHOLD = 5
const BRUTE_FORCE_WINDOW_MS = 15 * 60 * 1000 // 15 minutes

/**
 * Send telemetry to Phase 2 central collector
 */
function sendTelemetryToPhase2(eventType, data) {
  if (!PHASE2_CONFIG.ENABLED) return

  const telemetry = {
    hostId: PHASE2_CONFIG.HOST_ID,
    ts: new Date().toISOString(),
    source: 'iam-server',
    eventType: eventType,
    security: data
  }

  const postData = JSON.stringify(telemetry)
  const options = {
    hostname: PHASE2_CONFIG.TELEMETRY_HOST,
    port: PHASE2_CONFIG.TELEMETRY_PORT,
    path: '/ingest/telemetry',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    },
    timeout: 5000
  }

  const req = http.request(options, (res) => {
    if (res.statusCode === 200) {
      console.log(`[Phase2] Telemetry sent: ${eventType}`)
    }
  })

  req.on('error', () => { /* Silently fail */ })
  req.on('timeout', () => req.destroy())
  req.write(postData)
  req.end()
}

/**
 * Send CRITICAL alert to Phase 2 Response Controller
 */
function sendAlertToResponseController(alertType, data) {
  if (!PHASE2_CONFIG.ENABLED) return

  const alert = {
    severity: 'CRITICAL',
    event: alertType,
    hostId: data.hostId || PHASE2_CONFIG.HOST_ID,
    ts: new Date().toISOString(),
    source: 'iam-server',
    details: data
  }

  const postData = JSON.stringify(alert)
  const options = {
    hostname: PHASE2_CONFIG.RESPONSE_CONTROLLER_HOST,
    port: PHASE2_CONFIG.RESPONSE_CONTROLLER_PORT,
    path: '/alert',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    },
    timeout: 5000
  }

  const req = http.request(options, (res) => {
    let body = ''
    res.on('data', chunk => body += chunk)
    res.on('end', () => {
      try {
        const response = JSON.parse(body)
        if (response.action === 'isolate') {
          console.log(`[Phase2] 🚨 Response Controller action: ${response.action} for ${response.hostId}`)
        }
      } catch (e) { /* ignore */ }
    })
  })

  req.on('error', (err) => {
    console.warn(`[Phase2] Alert send failed: ${err.message}`)
  })
  req.on('timeout', () => req.destroy())
  req.write(postData)
  req.end()
}

/**
 * Track login failure and check for brute force
 */
function trackLoginFailure(ipAddress, email) {
  const now = Date.now()

  if (!loginFailureTracker.has(ipAddress)) {
    loginFailureTracker.set(ipAddress, { count: 0, firstFailure: now, emails: new Set() })
  }

  const tracker = loginFailureTracker.get(ipAddress)

  // Reset if window expired
  if (now - tracker.firstFailure > BRUTE_FORCE_WINDOW_MS) {
    tracker.count = 0
    tracker.firstFailure = now
    tracker.emails = new Set()
  }

  tracker.count++
  if (email) tracker.emails.add(email)

  // Send telemetry for every login failure
  sendTelemetryToPhase2('LOGIN_FAILURE', {
    ipAddress,
    email: email || 'unknown',
    failureCount: tracker.count,
    timestamp: new Date().toISOString()
  })

  // Check for brute force
  if (tracker.count >= BRUTE_FORCE_THRESHOLD) {
    console.error(`[SECURITY] 🚨 Brute force detected from IP: ${ipAddress}`)

    // Send CRITICAL alert to Response Controller
    sendAlertToResponseController('BRUTE_FORCE_ATTACK', {
      ipAddress,
      failureCount: tracker.count,
      targetedEmails: Array.from(tracker.emails),
      windowMinutes: BRUTE_FORCE_WINDOW_MS / 60000
    })

    return true // Indicates brute force detected
  }

  return false
}

const app = express()

console.log('Express app created')

// Security middleware: helmet for HTTP headers
app.use(helmet())

// CORS configuration (restrict in production)
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:5174',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:5174',
      process.env.CORS_ORIGIN
    ].filter(Boolean)
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true)
    } else {
      callback(new Error('Not allowed by CORS'))
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))

app.use(bodyParser.json({ limit: '1mb' })) // Limit payload size

const DATA_DIR = path.join(__dirname)
const USERS_FILE = path.join(DATA_DIR, 'users.json')
const DATA_FILE = path.join(DATA_DIR, 'data.json')
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json')

// ===== SECURITY: Environment Variables =====
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('ERROR: JWT_SECRET environment variable must be set in production!')
  process.exit(1)
}

const JWT_SECRET = process.env.JWT_SECRET || 'demo_key_only_change_in_production'
const ACCESS_TOKEN_TTL = '15m' // JWT expiry
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

// ===== RATE LIMITING =====
// Strict rate limit for login endpoint (5 attempts per 15 minutes per IP)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: { success: false, error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  skip: (req) => req.method !== 'POST' // Only rate limit POST requests
})

// Moderate rate limit for MFA verification (10 attempts per 15 minutes per IP)
const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: { success: false, error: 'Too many MFA attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method !== 'POST'
})

// General API rate limit (100 requests per 15 minutes per IP)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
})

// Apply general API limiter to all routes
app.use(apiLimiter)

// ===== PHASE 2: EDR Role-Aware Middleware =====
// Monitors all authenticated requests and sends role-tagged telemetry
if (createEdrMiddleware) {
  const edrTarget = `http://${PHASE2_CONFIG.TELEMETRY_HOST}:${PHASE2_CONFIG.TELEMETRY_PORT}/ingest/telemetry`
  app.use(createEdrMiddleware({
    hostId: 'hospital-iam',
    target: edrTarget,
    batchIntervalMs: 2000,
    maxBatchSize: 30
  }))
  console.log(`✓ EDR role-aware middleware active → ${edrTarget}`)
}

// Root endpoint
app.get('/', (req, res) => {
  res.json({ success: true, message: 'Hospital IAM Server running', version: '1.0.0' })
})

// Error handler middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message)
  res.status(500).json({ success: false, error: 'Server error', details: err.message })
})

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf8')
}

function readSessions() {
  try {
    return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'))
  } catch (e) {
    return { refreshTokens: {} }
  }
}

function writeSessions(obj) {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(obj, null, 2), 'utf8')
}

// On startup: migrate plaintext passwords to bcrypt hashes if needed
console.log('Starting user migration...')
try {
  const users = readJson(USERS_FILE)
  console.log('Users loaded:', Object.keys(users).length)
  let changed = false
  Object.entries(users).forEach(([email, u]) => {
    if (u.password && !u.password.startsWith('$2')) {
      const hash = bcrypt.hashSync(u.password, 10)
      users[email].password = hash
      changed = true
    }
  })
  if (changed) writeJson(USERS_FILE, users)
  console.log('User migration complete')
} catch (err) {
  console.warn('Could not migrate users.json', err.message)
}

const ROLE_PERMISSIONS = {
  admin: {
    canViewPatients: true,
    canEditPatients: true,
    canDeletePatients: true,
    canViewAppointments: true,
    canManageAppointments: true,
    canViewRecords: true,
    canEditRecords: true,
    canManageUsers: true,
    canViewReports: true,
    canAccessSettings: true,
    canViewPatientFiles: true,
    canDownloadFiles: true,
    canUploadFiles: true,
    canViewBilling: true,
    canEditBilling: true,
    canManageBilling: true,
    canViewLabs: true,
    canManageLabs: true,
    canViewPharmacy: true,
    canManagePharmacy: true,
    // Encryption permissions
    canDecryptLogs: true,
    canDecryptMedical: false,
    canDecryptBilling: false
  },
  doctor: {
    canViewPatients: true,
    canEditPatients: true,
    canDeletePatients: false,
    canViewAppointments: true,
    canManageAppointments: true,
    canViewRecords: true,
    canEditRecords: true,
    canManageUsers: false,
    canViewReports: true,
    canAccessSettings: false,
    canViewPatientFiles: true,
    canDownloadFiles: true,
    canUploadFiles: true,
    canViewBilling: true,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true,
    canManageLabs: false,
    canViewPharmacy: true,
    canManagePharmacy: false,
    // Encryption permissions - Doctor can decrypt all medical data
    canDecryptMedical: true,
    canDecryptLabReports: true,
    canDecryptPrescriptions: true,
    canDecryptVitals: true,
    canDecryptDiagnosis: true
  },
  nurse: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: true,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewPatientFiles: true,
    canDownloadFiles: false,
    canUploadFiles: false,
    canViewBilling: true,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Nurse can decrypt vitals and medication
    canDecryptVitals: true,
    canDecryptMedication: true,
    canDecryptNursingNotes: true,
    canDecryptMedical: false,
    canDecryptPrescriptions: false,
    canDecryptLabReports: false
  },
  receptionist: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: true,
    canManageAppointments: true,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewPatientFiles: false,
    canDownloadFiles: false,
    canUploadFiles: false,
    canViewBilling: true,
    canEditBilling: true,
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Receptionist can only decrypt demographic data
    canDecryptDemographics: true,
    canDecryptMedical: false,
    canDecryptLabReports: false,
    canDecryptPrescriptions: false
  },
  lab_technician: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewPatientFiles: true,
    canDownloadFiles: true,
    canUploadFiles: true,
    canViewBilling: false,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true,
    canManageLabs: true,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Lab tech can decrypt test type and patient name only
    canDecryptTestType: true,
    canDecryptPatientName: true,
    canDecryptMedical: false,
    canDecryptDiagnosis: false,
    canDecryptPrescriptions: false,
    canEncryptLabResults: true
  },
  pharmacist: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewPatientFiles: false,
    canDownloadFiles: false,
    canUploadFiles: false,
    canViewBilling: false,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: true,
    canManagePharmacy: true,
    // Encryption permissions - Pharmacist can decrypt medicine section only
    canDecryptMedicine: true,
    canDecryptDosage: true,
    canDecryptMedical: false,
    canDecryptDiagnosis: false,
    canDecryptLabReports: false
  },
  accountant: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewPatientFiles: false,
    canDownloadFiles: false,
    canUploadFiles: false,
    canViewBilling: true,
    canEditBilling: true,
    canManageBilling: true,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Accountant can decrypt billing data only
    canDecryptBilling: true,
    canDecryptInvoices: true,
    canDecryptInsurance: true,
    canDecryptMedical: false,
    canDecryptLabReports: false,
    canDecryptPrescriptions: false
  },
  patient: {
    canViewPatients: false,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewPatientFiles: true,
    canDownloadFiles: true,
    canUploadFiles: false,
    canViewBilling: true,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Patient can decrypt own medical data
    canDecryptOwnMedical: true,
    canDecryptOwnBilling: true,
    canDecryptMedical: false
  }
}

// Sessions are persisted refresh tokens stored in sessions.json

function createRandomToken() {
  return crypto.randomBytes(32).toString('hex')
}

app.post('/api/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {}
  console.log('[LOGIN] Request received:', { email, password: password ? '***' : undefined })
  
  if (!email || !password) {
    console.log('[LOGIN] Missing credentials')
    return res.status(400).json({ success: false, error: 'Missing credentials' })
  }

  // Input validation
  if (typeof email !== 'string' || typeof password !== 'string') {
    console.log('[LOGIN] Invalid input format')
    return res.status(400).json({ success: false, error: 'Invalid input format' })
  }

  if (email.length > 255 || password.length > 255) {
    console.log('[LOGIN] Input too long')
    return res.status(400).json({ success: false, error: 'Input too long' })
  }

  try {
    const users = readJson(USERS_FILE)
    console.log('[LOGIN] Available users:', Object.keys(users))

    // Case-insensitive email lookup
    const userEmail = Object.keys(users).find(key => key.toLowerCase() === email.toLowerCase())
    const user = userEmail ? users[userEmail] : null

    if (!user) {
      console.log('[LOGIN] User not found:', email)
      // Phase 2: Track login failure
      trackLoginFailure(req.ip || req.connection.remoteAddress || 'unknown', email)
      return res.json({ success: false, error: 'Invalid email or password' })
    }

    console.log('[LOGIN] User found, checking password')
    const pwOk = bcrypt.compareSync(password, user.password)
    console.log('[LOGIN] Password match:', pwOk)

    if (!pwOk) {
      console.log('[LOGIN] Password mismatch')
      // Phase 2: Track login failure
      trackLoginFailure(req.ip || req.connection.remoteAddress || 'unknown', email)
      return res.json({ success: false, error: 'Invalid email or password' })
    }

    if (user.mfaEnabled) {
      console.log('[LOGIN] MFA required for user:', userEmail)
      return res.json({ success: true, mfaRequired: true, message: 'MFA required' })
    }

    // Issue tokens - use the actual email from the database (preserves case)
    const accessToken = jwt.sign({ email: userEmail, role: user.role }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL })
    const refreshToken = createRandomToken()
    const sessionsObj = readSessions()
    sessionsObj.refreshTokens[refreshToken] = { email: userEmail, expiresAt: Date.now() + REFRESH_TTL_MS }
    writeSessions(sessionsObj)
    console.log('[LOGIN] Tokens issued, login successful')

    // Phase 2: Send successful login telemetry
    sendTelemetryToPhase2('LOGIN_SUCCESS', {
      ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
      email: userEmail,
      role: user.role,
      mfa: false,
      timestamp: new Date().toISOString()
    })

    return res.json({ success: true, mfaRequired: false, user: { email: userEmail, name: user.name, role: user.role, permissions: ROLE_PERMISSIONS[user.role] }, token: accessToken, refreshToken })
  } catch (err) {
    console.error('[LOGIN] Server error:', err)
    return res.status(500).json({ success: false, error: 'Server error' })
  }
})

app.post('/api/mfa/verify', mfaLimiter, (req, res) => {
  const { email, code } = req.body || {}
  if (!email || !code) return res.status(400).json({ success: false, error: 'Missing params' })

  // Input validation
  if (typeof email !== 'string' || typeof code !== 'string') {
    return res.status(400).json({ success: false, error: 'Invalid input format' })
  }

  // MFA code should be 6 digits
  if (!/^\d{6}$/.test(code.trim())) {
    return res.status(400).json({ success: false, error: 'Invalid MFA code format' })
  }

  try {
    const users = readJson(USERS_FILE)
    const user = users[email]
    if (!user) {
      // Phase 2: Track MFA failure for unknown user
      trackLoginFailure(req.ip || req.connection.remoteAddress || 'unknown', email)
      return res.json({ success: false, error: 'Unknown user' })
    }
    if (!user.mfaEnabled || !user.mfaSecret) return res.json({ success: false, error: 'MFA not configured' })

    const verified = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token: code.trim(), window: 1 })
    if (!verified) {
      // Phase 2: Track MFA code failure
      trackLoginFailure(req.ip || req.connection.remoteAddress || 'unknown', email)
      sendTelemetryToPhase2('MFA_FAILURE', {
        ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
        email,
        timestamp: new Date().toISOString()
      })
      return res.json({ success: false, error: 'Invalid MFA code' })
    }

    // Issue JWT access token and refresh token (persisted)
    const accessToken = jwt.sign({ email: email, role: user.role }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL })
    const refreshToken = createRandomToken()
    const sessionsObj = readSessions()
    sessionsObj.refreshTokens[refreshToken] = { email, expiresAt: Date.now() + REFRESH_TTL_MS }
    writeSessions(sessionsObj)

    // Phase 2: Send successful login telemetry
    sendTelemetryToPhase2('LOGIN_SUCCESS', {
      ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
      email,
      role: user.role,
      mfa: true,
      timestamp: new Date().toISOString()
    })

    return res.json({ success: true, user: { email, name: user.name, role: user.role, permissions: ROLE_PERMISSIONS[user.role] }, token: accessToken, refreshToken })
  } catch (err) {
    console.error('MFA verify error:', err)
    return res.status(500).json({ success: false, error: 'Server error' })
  }
})

// Middleware to protect routes via JWT access token (Authorization: Bearer <token>)
function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'] || ''
  const match = auth.match(/^Bearer (.+)$/)
  if (!match) return res.status(401).json({ success: false, error: 'Missing or invalid Authorization header' })
  const token = match[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.userEmail = payload.email
    req.userRole = payload.role
    next()
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Invalid or expired token' })
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    const users = readJson(USERS_FILE)
    const user = users[req.userEmail]
    const perms = ROLE_PERMISSIONS[user.role]
    if (!perms || !perms[permission]) return res.status(403).json({ success: false, error: 'Forbidden' })
    next()
  }
}

// Refresh token endpoint
app.post('/api/token/refresh', (req, res) => {
  const { refreshToken } = req.body || {}
  if (!refreshToken) return res.status(400).json({ success: false, error: 'Missing refreshToken' })
  const sessionsObj = readSessions()
  const rec = sessionsObj.refreshTokens[refreshToken]
  if (!rec) return res.status(401).json({ success: false, error: 'Invalid refresh token' })
  if (rec.expiresAt < Date.now()) {
    delete sessionsObj.refreshTokens[refreshToken]
    writeSessions(sessionsObj)
    return res.status(401).json({ success: false, error: 'Refresh token expired' })
  }
  // rotate tokens
  delete sessionsObj.refreshTokens[refreshToken]
  const newRefresh = createRandomToken()
  sessionsObj.refreshTokens[newRefresh] = { email: rec.email, expiresAt: Date.now() + REFRESH_TTL_MS }
  writeSessions(sessionsObj)
  const users = readJson(USERS_FILE)
  const user = users[rec.email]
  const accessToken = jwt.sign({ email: rec.email, role: user.role }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL })
  return res.json({ success: true, token: accessToken, refreshToken: newRefresh })
})

// Logout (revoke refresh token)
app.post('/api/logout', (req, res) => {
  const { refreshToken } = req.body || {}
  if (!refreshToken) return res.status(400).json({ success: false, error: 'Missing refreshToken' })
  const sessionsObj = readSessions()
  if (sessionsObj.refreshTokens[refreshToken]) {
    delete sessionsObj.refreshTokens[refreshToken]
    writeSessions(sessionsObj)
  }
  return res.json({ success: true })
})

app.get('/api/patients', authMiddleware, (req, res) => {
  const users = readJson(USERS_FILE)
  const user = users[req.userEmail]
  const perms = ROLE_PERMISSIONS[user.role]
  if (!perms || !perms.canViewPatients) return res.status(403).json({ success: false, error: 'Forbidden' })

  const data = readJson(DATA_FILE)
  return res.json({ success: true, patients: data.patients })
})

app.get('/api/appointments', authMiddleware, (req, res) => {
  const users = readJson(USERS_FILE)
  const user = users[req.userEmail]
  const perms = ROLE_PERMISSIONS[user.role]
  if (!perms || !perms.canViewAppointments) return res.status(403).json({ success: false, error: 'Forbidden' })

  const data = readJson(DATA_FILE)
  return res.json({ success: true, appointments: data.appointments })
})

app.get('/api/me', authMiddleware, (req, res) => {
  const users = readJson(USERS_FILE)
  const user = users[req.userEmail]
  const perms = ROLE_PERMISSIONS[user.role]
  return res.json({ success: true, user: { email: req.userEmail, name: user.name, role: user.role, permissions: perms } })
})

// Admin-provisioning endpoint to get or generate a user's MFA secret
app.get('/api/admin/mfa/secret', authMiddleware, requirePermission('canManageUsers'), (req, res) => {
  const email = req.query.email
  if (!email) return res.status(400).json({ success: false, error: 'Missing email' })
  const users = readJson(USERS_FILE)
  const user = users[email]
  if (!user) return res.status(404).json({ success: false, error: 'User not found' })
  if (!user.mfaSecret) {
    // generate and store a secret
    const secret = speakeasy.generateSecret({ length: 20 })
    user.mfaSecret = secret.base32
    users[email] = user
    writeJson(USERS_FILE, users)
  }
  return res.json({ success: true, secret: user.mfaSecret })
})

// ===== PHASE 2 INTEGRATION: User Token Revocation =====
// This endpoint is called by the Response Controller when isolating hosts
// to revoke all active sessions for a user
app.post('/api/security/revoke-user', (req, res) => {
  const { email, ipAddress, reason } = req.body || {}

  // Allow calls from Response Controller (no auth required for internal service calls)
  // In production, you'd want to validate this is from a trusted source
  const sourceIP = req.ip || req.connection.remoteAddress || 'unknown'
  console.log(`[SECURITY] Revoke request from ${sourceIP} for ${email || ipAddress || 'unknown'}`)

  if (!email && !ipAddress) {
    return res.status(400).json({ success: false, error: 'Missing email or ipAddress' })
  }

  let revokedCount = 0
  const sessionsObj = readSessions()

  if (email) {
    // Revoke all tokens for this email
    Object.keys(sessionsObj.refreshTokens).forEach(token => {
      if (sessionsObj.refreshTokens[token].email === email) {
        delete sessionsObj.refreshTokens[token]
        revokedCount++
      }
    })
  }

  if (ipAddress) {
    // Clear the brute force tracker for this IP (host is being isolated anyway)
    if (loginFailureTracker.has(ipAddress)) {
      loginFailureTracker.delete(ipAddress)
    }
  }

  writeSessions(sessionsObj)

  console.log(`[SECURITY] Revoked ${revokedCount} tokens for ${email || 'N/A'}, reason: ${reason}`)

  // Send telemetry about the revocation
  sendTelemetryToPhase2('USER_REVOKED', {
    email: email || 'N/A',
    ipAddress: ipAddress || 'N/A',
    revokedTokens: revokedCount,
    reason,
    timestamp: new Date().toISOString()
  })

  return res.json({
    success: true,
    revoked: email || ipAddress,
    tokensRevoked: revokedCount,
    message: `User sessions revoked due to: ${reason}`
  })
})

// ===== PHASE 2: IP Block Endpoint =====
// Called by Response Controller to block an IP
app.post('/api/security/block-ip', (req, res) => {
  const { ipAddress, reason, duration } = req.body || {}

  if (!ipAddress) {
    return res.status(400).json({ success: false, error: 'Missing ipAddress' })
  }

  // In a real system, you'd add this to a blocklist
  // For now, we just log it and send telemetry
  console.log(`[SECURITY] 🚫 IP Block requested: ${ipAddress}, reason: ${reason}`)

  sendTelemetryToPhase2('IP_BLOCKED', {
    ipAddress,
    reason,
    duration: duration || 'indefinite',
    timestamp: new Date().toISOString()
  })

  return res.json({ success: true, blocked: ipAddress, reason })
})

const PORT = process.env.PORT || 4000
const server = app.listen(PORT, () => {
  console.log(`Backend listening on http://localhost:${PORT}`)
})

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Trying next port...`)
    const newPort = PORT + 1
    app.listen(newPort, () => {
      console.log(`Backend listening on http://localhost:${newPort}`)
    })
  } else {
    console.error('Server error:', err)
  }
})

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err)
  process.exit(1)
})
