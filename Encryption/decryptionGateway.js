const storage = require('./storageManager');
const kms = require('./kms');
const encryption = require('./encryption');

async function checkIAM(user) {
  return true;
}
async function checkMFA(user) {
  return true;
}
async function checkDevicePosture(user) {
  return true;
}

async function sendLog(event, user, fileId, extra = {}) {
  const ts = new Date().toISOString();
  console.log(`[AUDIT] ${ts} ${event} user=${user?.id || user?.name || 'unknown'} file=${fileId} ${JSON.stringify(extra)}`);
}

async function decryptFileForUser(fileName, user) {
  if (!fileName) throw new Error('File name is required');
  if (!user) throw new Error('User object is required');

  await sendLog('attempt_decrypt', user, fileName);

  const allowed = await checkIAM(user);
  if (!allowed) {
    await sendLog('iam_denied', user, fileName);
    throw new Error('IAM check failed');
  }

  const mfaOk = await checkMFA(user);
  if (!mfaOk) {
    await sendLog('mfa_denied', user, fileName);
    throw new Error('MFA check failed');
  }

  const deviceOk = await checkDevicePosture(user);
  if (!deviceOk) {
    await sendLog('device_denied', user, fileName);
    throw new Error('Device posture check failed');
  }

  const allowedPermission = user.permissions && user.permissions.includes('canViewPatients');
  if (!allowedPermission) {
    await sendLog('permission_denied', user, fileName);
    throw new Error('User not authorized to decrypt this file');
  }

  try {
    const { encPath, metaPath } = storage.getStoragePaths(fileName);
    const tempPath = storage.getTempPath(fileName);

    const dek = await kms.getDEK(fileName);
    if (!dek) {
      await sendLog('no_dek', user, fileName);
      throw new Error('Key not found in KMS');
    }

    const plain = await encryption.decryptFile(encPath, metaPath, tempPath);

    await sendLog('decrypt_success', user, fileName, { tempPath });
    return { tempPath, plain };
  } catch (err) {
    await sendLog('decrypt_failed', user, fileName, { error: err.message });
    throw err;
  }
}

module.exports = { decryptFileForUser, checkIAM, checkMFA, checkDevicePosture, sendLog };
