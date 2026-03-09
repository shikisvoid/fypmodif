/**
 * iamIntegration.js
 * 
 * Integrates with the IAM service (port 4000) and MFA to verify user access
 * before allowing decryption. Replaces dummy IAM/MFA checks with real calls.
 */

const http = require('http');

const IAM_HOST = process.env.IAM_HOST || 'localhost';
const IAM_PORT = process.env.IAM_PORT || 4000;

/**
 * Call IAM service to verify user has permission to access file
 * @param {string} userId - User ID
 * @param {string} jwtToken - JWT token from user session
 * @returns {Promise<Object>} - User info if valid, null if invalid
 */
async function verifyWithIAM(userId, jwtToken) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: IAM_HOST,
      port: IAM_PORT,
      path: '/api/me',
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${jwtToken}`,
        'Content-Type': 'application/json'
      },
      timeout: 5000
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const response = JSON.parse(data);
            // Extract just the user object from the response
            const user = response.user || response;
            resolve(user);
          } else {
            resolve(null);
          }
        } catch (err) {
          reject(err);
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('IAM service timeout'));
    });

    req.end();
  });
}

/**
 * Verify MFA token
 * @param {string} userId - User ID
 * @param {string} mfaToken - OTP/TOTP token from user
 * @returns {Promise<boolean>} - true if MFA verified
 */
async function verifyMFA(userId, mfaToken) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      userId,
      mfaToken
    });

    const options = {
      hostname: IAM_HOST,
      port: IAM_PORT,
      path: '/api/mfa/verify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 5000
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const response = JSON.parse(data);
            resolve(response.success === true);
          } else {
            resolve(false);
          }
        } catch (err) {
          reject(err);
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('MFA service timeout'));
    });

    req.write(postData);
    req.end();
  });
}

/**
 * Check if user has decrypt permission
 * @param {Object} user - User object from IAM
 * @returns {boolean} - true if user can decrypt
 */
function checkUserPermissions(user) {
  // For now, allow any authenticated user to decrypt
  // In production, you would check specific permissions
  if (!user) {
    return false;
  }

  // Admin users always have permission
  if (user.role === 'admin') {
    return true;
  }

  // Check if user has permissions object
  if (user.permissions) {
    // If they have canViewRecords or canViewPatients, allow decrypt
    if (typeof user.permissions === 'object' && !Array.isArray(user.permissions)) {
      if (user.permissions.canViewRecords || user.permissions.canViewPatients || user.permissions.canManageUsers) {
        return true;
      }
    }
  }

  // Allow doctor and nurse roles
  if (user.role === 'doctor' || user.role === 'nurse') {
    return true;
  }

  return false;
}

/**
 * Main verification function: Combines IAM, MFA, and permissions
 * @param {string} userId - User ID
 * @param {string} jwtToken - JWT token
 * @param {string} mfaToken - OTP/TOTP token (optional if user has MFA disabled)
 * @returns {Promise<Object>} - User object if verified, throws error otherwise
 */
async function verifyUserAccess(userId, jwtToken, mfaToken = null) {
  try {
    // Step 1: Verify JWT with IAM
    console.log(`[IAM] Verifying JWT for user: ${userId}`);
    const user = await verifyWithIAM(userId, jwtToken);
    
    if (!user) {
      throw new Error('Invalid JWT token - IAM verification failed');
    }

    // Step 2: Verify MFA if user has it enabled
    if (user.mfaEnabled) {
      if (!mfaToken) {
        throw new Error('MFA token required - user has MFA enabled');
      }
      
      console.log(`[MFA] Verifying MFA token for user: ${userId}`);
      const mfaValid = await verifyMFA(userId, mfaToken);
      
      if (!mfaValid) {
        throw new Error('Invalid MFA token - MFA verification failed');
      }
    }

    // Step 3: Check permissions
    console.log(`[PERMISSIONS] Checking permissions for user: ${userId}`);
    console.log(`[PERMISSIONS] User object:`, JSON.stringify(user, null, 2));
    console.log(`[PERMISSIONS] User permissions:`, user.permissions);
    if (!checkUserPermissions(user)) {
      throw new Error('User does not have permission to decrypt files');
    }

    console.log(`[SUCCESS] User ${userId} verified and authorized for decryption`);
    return user;

  } catch (err) {
    console.error(`[ERROR] User access verification failed: ${err.message}`);
    throw err;
  }
}

module.exports = {
  verifyUserAccess,
  verifyWithIAM,
  verifyMFA,
  checkUserPermissions
};
