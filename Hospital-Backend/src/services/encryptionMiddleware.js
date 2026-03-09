/**
 * Encryption Middleware for Healthcare System
 * 
 * Provides role-based encryption/decryption middleware
 * with comprehensive audit logging
 */

const { encryptField, decryptField } = require('./fieldEncryption');
const logger = require('./logger');

// Field encryption configuration by table
const ENCRYPTED_FIELDS = {
  patients: {
    personal_info: { context: 'patient', roles: ['doctor', 'nurse', 'receptionist', 'admin'] },
    medical_history: { context: 'patient', roles: ['doctor', 'nurse', 'admin'] },
    insurance_info: { context: 'patient', roles: ['receptionist', 'accountant', 'admin'] },
    emergency_contact: { context: 'patient', roles: ['doctor', 'nurse', 'receptionist', 'admin'] }
  },
  lab_tests: {
    result_data: { context: 'lab', roles: ['doctor', 'lab_technician', 'admin'] },
    notes: { context: 'lab', roles: ['doctor', 'lab_technician', 'admin'] }
  },
  prescriptions: {
    medication_details: { context: 'prescription', roles: ['doctor', 'pharmacist', 'admin'] },
    dosage_instructions: { context: 'prescription', roles: ['doctor', 'pharmacist', 'nurse', 'admin'] }
  },
  billing: {
    payment_info: { context: 'billing', roles: ['accountant', 'receptionist', 'admin'] },
    insurance_claim: { context: 'billing', roles: ['accountant', 'admin'] }
  },
  mfa_secrets: {
    secret: { context: 'mfa', roles: ['system'] }
  }
};

/**
 * Check if user role can access encrypted field
 */
function canAccessField(table, field, userRole) {
  const config = ENCRYPTED_FIELDS[table]?.[field];
  if (!config) return true; // Not an encrypted field
  return config.roles.includes(userRole) || config.roles.includes('admin');
}

/**
 * Encrypt sensitive fields in data object
 */
function encryptSensitiveFields(table, data, userRole) {
  if (!data || typeof data !== 'object') return data;
  
  const tableConfig = ENCRYPTED_FIELDS[table];
  if (!tableConfig) return data;
  
  const encrypted = { ...data };
  for (const [field, config] of Object.entries(tableConfig)) {
    if (data[field] !== undefined && data[field] !== null) {
      // Check if already encrypted
      if (data[field]?.v && data[field]?.alg) continue;
      encrypted[field] = encryptField(data[field], config.context);
    }
  }
  return encrypted;
}

/**
 * Decrypt sensitive fields in data object
 */
function decryptSensitiveFields(table, data, userRole, userId, ipAddress) {
  if (!data || typeof data !== 'object') return data;
  
  const tableConfig = ENCRYPTED_FIELDS[table];
  if (!tableConfig) return data;
  
  const decrypted = { ...data };
  for (const [field, config] of Object.entries(tableConfig)) {
    if (data[field]?.v && data[field]?.alg) {
      if (canAccessField(table, field, userRole)) {
        try {
          decrypted[field] = decryptField(data[field], config.context);
          // Log successful decryption
          logger.logEncryption(logger.AUDIT_EVENTS.FILE_DECRYPTED, {
            userId,
            userRole,
            ipAddress,
            resourceType: table,
            details: { field, context: config.context },
            status: 'success'
          });
        } catch (error) {
          decrypted[field] = '[DECRYPTION_ERROR]';
          logger.logEncryption(logger.AUDIT_EVENTS.DECRYPT_DENIED, {
            userId,
            userRole,
            ipAddress,
            resourceType: table,
            severity: logger.SEVERITY.ERROR,
            details: { field, error: error.message },
            status: 'failure'
          });
        }
      } else {
        decrypted[field] = '[ACCESS_DENIED]';
        logger.logEncryption(logger.AUDIT_EVENTS.DECRYPT_DENIED, {
          userId,
          userRole,
          ipAddress,
          resourceType: table,
          severity: logger.SEVERITY.WARN,
          details: { field, reason: 'insufficient_permissions' },
          status: 'denied'
        });
      }
    }
  }
  return decrypted;
}

/**
 * Express middleware for automatic decryption
 */
function decryptionMiddleware(table) {
  return (req, res, next) => {
    const originalJson = res.json.bind(res);
    res.json = (data) => {
      if (req.user && data) {
        const ip = req.ip || req.connection?.remoteAddress;
        if (Array.isArray(data)) {
          data = data.map(item => decryptSensitiveFields(table, item, req.user.role, req.user.id, ip));
        } else if (data.data && Array.isArray(data.data)) {
          data.data = data.data.map(item => decryptSensitiveFields(table, item, req.user.role, req.user.id, ip));
        } else {
          data = decryptSensitiveFields(table, data, req.user.role, req.user.id, ip);
        }
      }
      return originalJson(data);
    };
    next();
  };
}

module.exports = {
  ENCRYPTED_FIELDS,
  canAccessField,
  encryptSensitiveFields,
  decryptSensitiveFields,
  decryptionMiddleware
};

