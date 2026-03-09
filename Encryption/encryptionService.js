/**
 * encryptionService.js
 * 
 * Wrapper for encryption/decryption with IAM/MFA integration
 * Called by Hospital-Backend API endpoints
 */

const path = require('path');
const fs = require('fs').promises;
const iamIntegration = require('./iamIntegration');
const storageManager = require('./storageManager');
const encryption = require('./encryption');
const kms = require('./kms');

/**
 * Decrypt file for authenticated user
 * Verifies user permissions before decryption
 */
async function decryptFileWithIAM(fileId, userId, jwtToken, mfaToken = null) {
  try {
    // Verify user with IAM + MFA
    const user = await iamIntegration.verifyUserAccess(userId, jwtToken, mfaToken);

    console.log(`[DECRYPT] Decrypting file for authorized user: ${user.id} (${user.name})`);
    
    // Get storage paths
    const { encPath, metaPath } = storageManager.getStoragePaths(fileId);
    const tempPath = storageManager.getTempPath(fileId);

    // Verify files exist
    try {
      await fs.access(encPath);
      await fs.access(metaPath);
    } catch {
      throw new Error(`File not found: ${fileId}`);
    }

    // Get DEK from KMS
    const dek = await kms.getDEK(fileId);
    if (!dek) {
      throw new Error('Decryption key not found in KMS');
    }

    // Decrypt file
    const plain = await encryption.decryptFile(encPath, metaPath, tempPath);

    // Schedule temp file deletion (auto-delete after 5 minutes)
    const deleteTimeoutMs = 5 * 60 * 1000;
    setTimeout(async () => {
      try {
        await fs.unlink(tempPath);
        console.log(`[CLEANUP] Temporary file deleted: ${tempPath}`);
      } catch (err) {
        console.error(`[CLEANUP] Failed to delete temp file: ${err.message}`);
      }
    }, deleteTimeoutMs);

    // Audit log
    console.log(`[AUDIT] DECRYPT_SUCCESS user=${user.id} file=${fileId} timestamp=${new Date().toISOString()}`);

    return {
      success: true,
      fileId,
      fileName: fileId,
      user: {
        id: user.id,
        name: user.name,
        role: user.role
      },
      tempPath,
      content: plain.toString(),
      decryptedAt: new Date().toISOString(),
      autoDeleteIn: '5 minutes'
    };

  } catch (err) {
    console.error(`[DECRYPT] Error: ${err.message}`);
    throw err;
  }
}

/**
 * Encrypt file and store in KMS
 */
async function encryptFileWithMetadata(sourceFilePath, fileId, userId, userRole) {
  try {
    console.log(`[ENCRYPT] Encrypting file: ${fileId} for user: ${userId}`);

    // Get storage paths
    const { encPath, metaPath } = storageManager.getStoragePaths(fileId);

    // Encrypt file
    await encryption.encryptFile(sourceFilePath, encPath, metaPath);

    // Store DEK in KMS
    await kms.createKey(fileId);

    // Cleanup temp file
    try {
      await fs.unlink(sourceFilePath);
    } catch (err) {
      console.error(`Failed to cleanup temp file: ${err.message}`);
    }

    // Audit log
    console.log(`[AUDIT] ENCRYPT_SUCCESS user=${userId} role=${userRole} file=${fileId} timestamp=${new Date().toISOString()}`);

    return {
      success: true,
      fileId,
      encryptedPath: encPath,
      metadataPath: metaPath,
      algorithm: 'AES-256-GCM',
      encryptedAt: new Date().toISOString(),
      user: {
        id: userId,
        role: userRole
      }
    };

  } catch (err) {
    console.error(`[ENCRYPT] Error: ${err.message}`);
    throw err;
  }
}

/**
 * Encrypt sensitive billing data (string fields)
 * Used for payment_method, discount_reason, insurance_details
 */
async function encryptBillingField(plainValue, billId, userId, userRole) {
  try {
    if (!plainValue) return null;

    const { _internal } = encryption;
    const dek = _internal.genDEK();
    const { ciphertext, iv, tag } = _internal.aesGcmEncrypt(
      Buffer.from(plainValue, 'utf8'),
      dek
    );

    // For demo: wrap DEK with MEK (production should use proper KMS)
    const MEK_B64 = process.env.DEMO_MEK_BASE64;
    const MEK = MEK_B64 ? Buffer.from(MEK_B64, 'base64') : null;
    
    let wrappedDEK = null, wrappedIV = null, wrappedTag = null;
    if (MEK) {
      const wrapped = _internal.aesGcmEncrypt(dek, MEK);
      wrappedDEK = wrapped.ciphertext.toString('base64');
      wrappedIV = wrapped.iv.toString('base64');
      wrappedTag = wrapped.tag.toString('base64');
    }

    const encryptedData = {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      wrappedDEK,
      wrappedIV,
      wrappedTag,
      algorithm: 'AES-256-GCM',
      encryptedAt: new Date().toISOString()
    };

    console.log(`[AUDIT] ENCRYPT_BILLING user=${userId} role=${userRole} bill=${billId} timestamp=${new Date().toISOString()}`);

    return encryptedData;
  } catch (err) {
    console.error(`[ENCRYPT_BILLING] Error: ${err.message}`);
    throw err;
  }
}

/**
 * Decrypt sensitive billing data (string fields)
 * Used for payment_method, discount_reason, insurance_details
 */
async function decryptBillingField(encryptedData, userId, userRole) {
  try {
    if (!encryptedData || !encryptedData.ciphertext) return null;

    const { _internal } = encryption;
    const MEK_B64 = process.env.DEMO_MEK_BASE64;
    const MEK = MEK_B64 ? Buffer.from(MEK_B64, 'base64') : null;

    let dek = null;
    if (MEK && encryptedData.wrappedDEK) {
      const wrappedDEK = Buffer.from(encryptedData.wrappedDEK, 'base64');
      const wrappedIV = Buffer.from(encryptedData.wrappedIV, 'base64');
      const wrappedTag = Buffer.from(encryptedData.wrappedTag, 'base64');
      dek = _internal.aesGcmDecrypt(
        { ciphertext: wrappedDEK, iv: wrappedIV, tag: wrappedTag },
        MEK
      );
    } else {
      throw new Error('Decryption key not found');
    }

    const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const tag = Buffer.from(encryptedData.tag, 'base64');

    const plainBuf = _internal.aesGcmDecrypt(
      { ciphertext, iv, tag },
      dek
    );

    const plainValue = plainBuf.toString('utf8');

    console.log(`[AUDIT] DECRYPT_BILLING user=${userId} role=${userRole} timestamp=${new Date().toISOString()}`);

    return plainValue;
  } catch (err) {
    console.error(`[DECRYPT_BILLING] Error: ${err.message}`);
    throw err;
  }
}

/**
 * Encrypt entire billing object with sensitive fields
 */
async function encryptBillingObject(billingObj, userId, userRole) {
  try {
    const encrypted = { ...billingObj };

    if (billingObj.payment_method) {
      encrypted.payment_method_encrypted = await encryptBillingField(
        billingObj.payment_method,
        billingObj.id,
        userId,
        userRole
      );
      delete encrypted.payment_method;
    }

    if (billingObj.discount_reason) {
      encrypted.discount_reason_encrypted = await encryptBillingField(
        billingObj.discount_reason,
        billingObj.id,
        userId,
        userRole
      );
      delete encrypted.discount_reason;
    }

    if (billingObj.insurance_details) {
      encrypted.insurance_details_encrypted = await encryptBillingField(
        JSON.stringify(billingObj.insurance_details),
        billingObj.id,
        userId,
        userRole
      );
      delete encrypted.insurance_details;
    }

    return encrypted;
  } catch (err) {
    console.error(`[ENCRYPT_OBJECT] Error: ${err.message}`);
    throw err;
  }
}

/**
 * Decrypt entire billing object with sensitive fields
 */
async function decryptBillingObject(billingObj, userId, userRole) {
  try {
    const decrypted = { ...billingObj };

    if (billingObj.payment_method_encrypted) {
      decrypted.payment_method = await decryptBillingField(
        billingObj.payment_method_encrypted,
        userId,
        userRole
      );
      delete decrypted.payment_method_encrypted;
    }

    if (billingObj.discount_reason_encrypted) {
      decrypted.discount_reason = await decryptBillingField(
        billingObj.discount_reason_encrypted,
        userId,
        userRole
      );
      delete decrypted.discount_reason_encrypted;
    }

    if (billingObj.insurance_details_encrypted) {
      const decryptedStr = await decryptBillingField(
        billingObj.insurance_details_encrypted,
        userId,
        userRole
      );
      decrypted.insurance_details = JSON.parse(decryptedStr);
      delete decrypted.insurance_details_encrypted;
    }

    return decrypted;
  } catch (err) {
    console.error(`[DECRYPT_OBJECT] Error: ${err.message}`);
    throw err;
  }
}

module.exports = {
  decryptFileWithIAM,
  encryptFileWithMetadata,
  encryptBillingField,
  decryptBillingField,
  encryptBillingObject,
  decryptBillingObject
};
