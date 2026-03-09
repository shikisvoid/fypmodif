/**
 * Field-Level Encryption Service
 * AES-256-GCM encryption for sensitive database fields
 * 
 * Implements encryption at rest for:
 * - Patient: personal info, medical history, insurance
 * - LabTests: lab values, report text
 * - Prescriptions: prescription text, medication, dosage
 * - Billing: fees, payment info
 * - Messages: appointment notifications
 * - MFA_Secrets: secret keys
 */

const crypto = require('crypto');

// Encryption Configuration
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const SALT_LENGTH = 32;

// Master Encryption Key (MEK) - In production, use proper KMS/HSM
const getMasterKey = () => {
  const mekB64 = process.env.MASTER_ENCRYPTION_KEY || process.env.DEMO_MEK_BASE64;
  if (mekB64) {
    return Buffer.from(mekB64, 'base64');
  }
  // Generate deterministic key for demo (NOT for production!)
  return crypto.scryptSync('hospital-demo-key-2024', 'hospital-salt', 32);
};

// Role-based encryption keys (derived from MEK)
const deriveRoleKey = (role) => {
  const mek = getMasterKey();
  return crypto.scryptSync(mek, `role-${role}-salt`, 32);
};

// User-specific encryption key (for MFA secrets)
const deriveUserKey = (userId) => {
  const mek = getMasterKey();
  return crypto.scryptSync(mek, `user-${userId}-mfa-salt`, 32);
};

/**
 * Encrypt a field value
 * @param {string|object} plainValue - Value to encrypt
 * @param {string} context - Context for key derivation (e.g., 'patient', 'billing')
 * @returns {object} Encrypted data object
 */
function encryptField(plainValue, context = 'default') {
  if (plainValue === null || plainValue === undefined) return null;
  
  try {
    const valueStr = typeof plainValue === 'object' 
      ? JSON.stringify(plainValue) 
      : String(plainValue);
    
    const key = context.startsWith('mfa-') 
      ? deriveUserKey(context.replace('mfa-', ''))
      : deriveRoleKey(context);
    
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    let encrypted = cipher.update(valueStr, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const tag = cipher.getAuthTag();
    
    return {
      v: 1, // Version for future migration
      alg: ALGORITHM,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      data: encrypted,
      ctx: context,
      ts: new Date().toISOString()
    };
  } catch (error) {
    console.error('[ENCRYPTION] encryptField error:', error.message);
    throw new Error('Encryption failed');
  }
}

/**
 * Decrypt a field value
 * @param {object} encryptedObj - Encrypted data object
 * @param {string} context - Context for key derivation
 * @returns {string|object} Decrypted value
 */
function decryptField(encryptedObj, context = 'default') {
  if (!encryptedObj || !encryptedObj.data) return null;
  
  try {
    const ctx = encryptedObj.ctx || context;
    const key = ctx.startsWith('mfa-') 
      ? deriveUserKey(ctx.replace('mfa-', ''))
      : deriveRoleKey(ctx);
    
    const iv = Buffer.from(encryptedObj.iv, 'base64');
    const tag = Buffer.from(encryptedObj.tag, 'base64');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encryptedObj.data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Try to parse as JSON
    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  } catch (error) {
    console.error('[DECRYPTION] decryptField error:', error.message);
    throw new Error('Decryption failed - invalid key or corrupted data');
  }
}

/**
 * Encrypt file content
 * @param {Buffer} fileBuffer - File content
 * @param {string} context - Encryption context
 * @returns {object} Encrypted file data
 */
function encryptFile(fileBuffer, context = 'file') {
  const key = deriveRoleKey(context);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  
  const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  return {
    v: 1,
    alg: ALGORITHM,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: encrypted.toString('base64'),
    ctx: context,
    ts: new Date().toISOString()
  };
}

/**
 * Decrypt file content
 * @param {object} encryptedObj - Encrypted file object
 * @param {string} context - Decryption context
 * @returns {Buffer} Decrypted file content
 */
function decryptFile(encryptedObj, context = 'file') {
  const ctx = encryptedObj.ctx || context;
  const key = deriveRoleKey(ctx);
  const iv = Buffer.from(encryptedObj.iv, 'base64');
  const tag = Buffer.from(encryptedObj.tag, 'base64');
  const data = Buffer.from(encryptedObj.data, 'base64');
  
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

module.exports = {
  encryptField, decryptField, encryptFile, decryptFile,
  deriveUserKey, deriveRoleKey, ALGORITHM
};

