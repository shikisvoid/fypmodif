/**
 * src/routes/lab.js
 * Lab Technician Portal API Endpoints
 * Handles test orders, sample collection, result uploads with encryption
 */

const express = require('express');
const router = express.Router();
const multer = require('multer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const tempFileManager = require('../services/tempFileManager');

// Encryption service (your existing encryption module)
let encryptionService;
try {
  encryptionService = require('../../Encryption/encryptionService');
} catch (err) {
  console.warn('Encryption service not available');
}

// Configure multer for file uploads (memory storage for encryption)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['application/pdf', 'image/png', 'image/jpeg', 'application/json'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, PNG, JPEG, JSON allowed.'));
    }
  }
});

// Middleware for authentication and role check
const authenticate = (req, res, next) => {
  // This should be implemented by your existing auth middleware
  if (!req.user || !req.user.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  next();
};

const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    }
    next();
  };
};

// Encryption helper functions
function encryptData(data, kek) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return {
    encrypted: encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

function decryptData(encrypted, iv, tag, kek) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

function generateHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ✅ 1. GET /api/lab/dashboard - Lab Tech Dashboard
router.get('/dashboard', authenticate, requireRole(['lab_technician']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const techId = req.user.userId;

    // Get stats
    const pending = await db('lab_tests').where('status', 'pending').count('* as count').first();
    const collected = await db('lab_tests').where('status', 'collected').count('* as count').first();
    const completed = await db('lab_tests').where('status', 'completed').count('* as count').first();
    const total = await db('lab_tests').count('* as count').first();

    res.json({
      success: true,
      dashboard: {
        pending: pending.count || 0,
        collected: collected.count || 0,
        completed: completed.count || 0,
        total: total.count || 0
      }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ success: false, error: 'Failed to load dashboard' });
  }
});

// ✅ 2. GET /api/lab/tests - Get Lab Tests for Technician
router.get('/tests', authenticate, requireRole(['lab_technician']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const status = req.query.status || 'pending'; // pending, collected, completed

    const tests = await db('lab_tests')
      .select('lab_tests.*', 'patients.name as patient_name', 'users.name as doctor_name')
      .join('patients', 'lab_tests.patient_id', 'patients.id')
      .join('users', 'lab_tests.doctor_id', 'users.id')
      .where('lab_tests.status', status)
      .orderBy('lab_tests.ordered_at', 'asc');

    // Mask patient names for privacy
    const maskedTests = tests.map(t => ({
      ...t,
      patient_name: maskPatientName(t.patient_name)
    }));

    res.json({
      success: true,
      tests: maskedTests
    });
  } catch (error) {
    console.error('Get tests error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch tests' });
  }
});

// ✅ 3. POST /api/lab/samples - Collect Sample
router.post('/samples', authenticate, requireRole(['lab_technician']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const { testId, sampleType, barcode, notes } = req.body;

    if (!testId || !sampleType) {
      return res.status(400).json({ success: false, error: 'Test ID and sample type required' });
    }

    // Get test
    const test = await db('lab_tests').where('id', testId).first();
    if (!test) {
      return res.status(404).json({ success: false, error: 'Test not found' });
    }

    // Create sample
    const sampleId = uuidv4();
    await db('lab_samples').insert({
      id: sampleId,
      test_id: testId,
      collected_by: req.user.userId,
      barcode: barcode || null,
      sample_type: sampleType,
      notes: notes || null,
      collected_at: new Date()
    });

    // Update test status
    await db('lab_tests').where('id', testId).update({ status: 'collected' });

    // Audit log
    await logAuditAction(db, {
      userId: req.user.userId,
      action: 'collected_sample',
      resourceType: 'test',
      resourceId: testId,
      status: 'success'
    });

    res.json({
      success: true,
      message: 'Sample collected',
      sampleId: sampleId
    });
  } catch (error) {
    console.error('Sample collection error:', error);
    res.status(500).json({ success: false, error: 'Failed to collect sample' });
  }
});

// ✅ 4. POST /api/lab/results - Upload Lab Results (with encryption)
router.post('/results', authenticate, requireRole(['lab_technician']), upload.single('reportFile'), async (req, res) => {
  try {
    const db = req.app.get('db');
    const { testId, sampleId, resultValues, techniciannotes, resultCategory } = req.body;
    const file = req.file;

    if (!testId || !sampleId) {
      return res.status(400).json({ success: false, error: 'Test ID and sample ID required' });
    }

    // Get KEK (KMS key) - in production this comes from KMS
    const kek = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

    // Encrypt result values if provided
    let resultValuesEncrypted = null, resultValuesIv = null, resultValuesTag = null;
    if (resultValues) {
      const encrypted = encryptData(JSON.parse(resultValues), kek);
      resultValuesEncrypted = encrypted.encrypted;
      resultValuesIv = encrypted.iv;
      resultValuesTag = encrypted.tag;
    }

    // Encrypt technician notes
    let notesEncrypted = null, notesIv = null, notesTag = null;
    if (techniciannotes) {
      const encrypted = encryptData({ notes: techniciannotes }, kek);
      notesEncrypted = encrypted.encrypted;
      notesIv = encrypted.iv;
      notesTag = encrypted.tag;
    }

    // Encrypt file if uploaded
    let fileEncrypted = null, fileIv = null, fileTag = null, fileHash = null, fileMimeType = null;
    if (file) {
      // Compute hash before encryption
      fileHash = generateHash(file.buffer);
      fileMimeType = file.mimetype;

      // Encrypt file
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), iv);
      let encrypted = cipher.update(file.buffer);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const tag = cipher.getAuthTag();

      fileEncrypted = encrypted.toString('hex');
      fileIv = iv.toString('hex');
      fileTag = tag.toString('hex');
    }

    // Generate DEK (Data Encryption Key) for this result
    const dek = crypto.randomBytes(32).toString('hex');
    const dekIv = crypto.randomBytes(16);
    const dekCipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), dekIv);
    let dekEncrypted = dekCipher.update(dek, 'hex', 'hex');
    dekEncrypted += dekCipher.final('hex');
    const dekTag = dekCipher.getAuthTag();

    // Save result
    const resultId = uuidv4();
    await db('lab_results').insert({
      id: resultId,
      test_id: testId,
      sample_id: sampleId,
      technician_id: req.user.userId,
      result_values_encrypted: resultValuesEncrypted,
      result_values_iv: resultValuesIv,
      result_values_tag: resultValuesTag,
      report_file_encrypted: fileEncrypted,
      report_file_iv: fileIv,
      report_file_tag: fileTag,
      report_file_hash: fileHash,
      report_file_mime_type: fileMimeType,
      technician_notes_encrypted: notesEncrypted,
      technician_notes_iv: notesIv,
      technician_notes_tag: notesTag,
      dek_encrypted_with_kek: `${dekEncrypted}:${dekIv.toString('hex')}:${dekTag.toString('hex')}`,
      result_category: resultCategory || 'Normal',
      status: 'completed',
      completed_at: new Date()
    });

    // Update test status
    await db('lab_tests').where('id', testId).update({ status: 'completed' });

    // Audit log
    await logAuditAction(db, {
      userId: req.user.userId,
      action: 'uploaded_result',
      resourceType: 'test',
      resourceId: testId,
      status: 'success',
      details: { fileSize: file ? file.size : 0, fileHash }
    });

    res.json({
      success: true,
      message: 'Lab results uploaded successfully',
      resultId: resultId,
      fileHash: fileHash
    });
  } catch (error) {
    console.error('Upload results error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload results' });
  }
});

// ✅ 5. GET /api/lab/results/:testId - Get Results (with decryption)
// ✅ FIXED: Doctors can now decrypt their own lab reports
router.get('/results/:testId', authenticate, requireRole(['doctor','lab_technician','nurse']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const { testId } = req.params;

    // Check permissions - only doctor, tech, nurse, or admin can view
    const test = await db('lab_tests').where('id', testId).first();
    if (!test) {
      return res.status(404).json({ success: false, error: 'Test not found' });
    }

    // Access control:
    // - Doctor can view if they ordered the test
    // - Lab technician can view any result
    // - Nurse can view any result
    if (req.user.role === 'doctor' && req.user.userId !== test.doctor_id) {
      return res.status(403).json({ success: false, error: 'Access denied - you can only view your own ordered tests' });
    }

    const results = await db('lab_results').where('test_id', testId).first();
    if (!results) {
      return res.status(404).json({ success: false, error: 'No results found' });
    }

    // Get KEK for decryption
    const kek = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

    // Decrypt data if present
    let decryptedValues = null;
    if (results.result_values_encrypted) {
      decryptedValues = decryptData(results.result_values_encrypted, results.result_values_iv, results.result_values_tag, kek);
    }

    let decryptedNotes = null;
    if (results.technician_notes_encrypted) {
      decryptedNotes = decryptData(results.technician_notes_encrypted, results.technician_notes_iv, results.technician_notes_tag, kek);
    }

    // Audit log for view
    await logAuditAction(db, {
      userId: req.user.userId,
      action: 'viewed_result',
      resourceType: 'result',
      resourceId: results.id,
      status: 'success'
    });

    res.json({
      success: true,
      result: {
        id: results.id,
        resultValues: decryptedValues,
        techniciannotes: decryptedNotes ? decryptedNotes.notes : null,
        resultCategory: results.result_category,
        completedAt: results.completed_at,
        fileHash: results.report_file_hash,
        fileMimeType: results.report_file_mime_type
      }
    });
  } catch (error) {
    console.error('Get results error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch results' });
  }
});

// ✅ 5b. GET /api/lab/results/:testId/download - Decrypt & download stored report file
// ✅ FIXED: Doctors can now decrypt their lab reports, files stored in temp with auto-cleanup
router.get('/results/:testId/download', authenticate, requireRole(['doctor','lab_technician','nurse']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const { testId } = req.params;

    const test = await db('lab_tests').where('id', testId).first();
    if (!test) return res.status(404).json({ success: false, error: 'Test not found' });

    // Access control: only ordering doctor, lab technicians, or nurses
    if (req.user.role === 'doctor' && req.user.userId !== test.doctor_id) {
      return res.status(403).json({ success: false, error: 'Access denied - you can only download your own test reports' });
    }

    const results = await db('lab_results').where('test_id', testId).first();
    if (!results || !results.report_file_encrypted) {
      return res.status(404).json({ success: false, error: 'No report file found' });
    }

    // Get KEK for decryption
    const kek = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

    // Decrypt file
    const encryptedHex = results.report_file_encrypted;
    const fileIv = results.report_file_iv;
    const fileTag = results.report_file_tag;

    try {
      const encryptedBuffer = Buffer.from(encryptedHex, 'hex');
      const ivBuf = Buffer.from(fileIv, 'hex');
      const tagBuf = Buffer.from(fileTag, 'hex');

      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), ivBuf);
      decipher.setAuthTag(tagBuf);
      const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

      // Save to session-specific temp directory with auto-cleanup
      const sessionId = req.session?.id || crypto.randomBytes(8).toString('hex');
      const tempFilename = `${testId}-${Date.now()}.pdf`;
      const tempPath = await tempFileManager.saveTempFile(req.user.userId, sessionId, tempFilename, decrypted);

      console.log(`✓ Decrypted report for test ${testId}, stored in temp: ${tempPath}`);
      console.log(`  Auto-cleanup scheduled in ${tempFileManager.CLEANUP_TIMEOUT / 1000 / 60} minutes`);

      // Audit log: download
      await logAuditAction(db, {
        userId: req.user.userId,
        action: 'downloaded_report',
        resourceType: 'lab_report_pdf',
        resourceId: results.id,
        status: 'success',
        details: { tempPath, sessionId, willAutoCleanup: true }
      });

      // Send file
      res.set('Content-Type', results.report_file_mime_type || 'application/pdf');
      const filename = `${test.test_name.replace(/[^a-z0-9-_\.]/gi, '_')}-${testId}.pdf`;
      res.set('Content-Disposition', `attachment; filename="${filename}"`);
      return res.send(decrypted);
    } catch (err) {
      console.error('File decryption error:', err);
      return res.status(500).json({ success: false, error: 'Failed to decrypt report file: ' + err.message });
    }

  } catch (error) {
    console.error('Download results error:', error);
    res.status(500).json({ success: false, error: 'Failed to download results' });
  }
});

// ✅ 6. GET /api/lab/audit-logs - View Audit Logs
router.get('/audit-logs', authenticate, requireRole(['lab_technician', 'admin']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const limit = req.query.limit || 50;

    const logs = await db('lab_audit_logs')
      .select('lab_audit_logs.*', 'users.name as user_name')
      .join('users', 'lab_audit_logs.user_id', 'users.id')
      .orderBy('lab_audit_logs.created_at', 'desc')
      .limit(limit);

    res.json({
      success: true,
      logs: logs
    });
  } catch (error) {
    console.error('Audit logs error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch audit logs' });
  }
});

// Helper function: Mask patient name
function maskPatientName(name) {
  if (!name || name.length < 2) return '***';
  const parts = name.split(' ');
  return parts.map((p, i) => {
    if (i === 0) return p.charAt(0) + '*'.repeat(p.length - 1);
    return '*'.repeat(p.length);
  }).join(' ');
}

// Helper function: Log audit action
async function logAuditAction(db, { userId, action, resourceType, resourceId, resourceName, status, reason, details }) {
  const logId = uuidv4();
  const logHash = crypto.createHash('sha256').update(JSON.stringify({ action, resourceId, userId })).digest('hex');

  await db('lab_audit_logs').insert({
    id: logId,
    user_id: userId,
    action: action,
    resource_type: resourceType,
    resource_id: resourceId,
    resource_name: resourceName || null,
    status: status || 'success',
    reason_denied: reason || null,
    details: details ? JSON.stringify(details) : null,
    log_hash: logHash,
    created_at: new Date()
  });
}

// ✅ 7. POST /api/lab/results/:testId/encrypt - Encrypt lab report PDF
router.post('/results/:testId/encrypt', authenticate, requireRole(['doctor', 'lab_technician']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const { testId } = req.params;
    const userId = req.user.userId;

    // Get test
    const test = await db('lab_tests').where('id', testId).first();
    if (!test) {
      return res.status(404).json({ success: false, error: 'Test not found' });
    }

    // Get or generate PDF
    let pdfBuffer;
    try {
      const response = await fetch(`http://localhost:3000/api/lab-tests/${testId}/pdf`, {
        headers: { 'Authorization': `Bearer ${req.get('Authorization')?.replace('Bearer ', '')}` }
      });
      
      if (!response.ok) {
        throw new Error('Failed to generate PDF');
      }
      
      pdfBuffer = await response.buffer();
    } catch (err) {
      console.error('PDF generation error:', err);
      return res.status(500).json({ success: false, error: 'Failed to generate PDF for encryption' });
    }

    // Encrypt PDF using AES-256-GCM
    const kek = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), iv);
    let encrypted = cipher.update(pdfBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const tag = cipher.getAuthTag();

    // Save to database
    const results = await db('lab_results').where('test_id', testId).first();
    
    if (results) {
      await db('lab_results').where('test_id', testId).update({
        report_file_encrypted: encrypted.toString('hex'),
        report_file_iv: iv.toString('hex'),
        report_file_tag: tag.toString('hex'),
        encryption_status: 'encrypted',
        encrypted_at: new Date(),
        encrypted_by: userId
      });
    } else {
      const resultId = uuidv4();
      await db('lab_results').insert({
        id: resultId,
        test_id: testId,
        report_file_encrypted: encrypted.toString('hex'),
        report_file_iv: iv.toString('hex'),
        report_file_tag: tag.toString('hex'),
        encryption_status: 'encrypted',
        encrypted_at: new Date(),
        encrypted_by: userId,
        status: 'completed',
        completed_at: new Date()
      });
    }

    // Audit log
    await logAuditAction(db, {
      userId: userId,
      action: 'encrypted_report',
      resourceType: 'lab_report',
      resourceId: testId,
      status: 'success'
    });

    res.json({
      success: true,
      message: 'Lab report encrypted successfully',
      testId: testId,
      encryptedAt: new Date().toISOString(),
      status: 'encrypted'
    });

  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({ success: false, error: 'Failed to encrypt report' });
  }
});

// ✅ 8. POST /api/lab/results/:testId/decrypt - Decrypt and download lab report
router.post('/results/:testId/decrypt', authenticate, requireRole(['doctor', 'lab_technician']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const { testId } = req.params;
    const userId = req.user.userId;

    // Get test
    const test = await db('lab_tests').where('id', testId).first();
    if (!test) {
      return res.status(404).json({ success: false, error: 'Test not found' });
    }

    // Get encrypted result
    const results = await db('lab_results').where('test_id', testId).first();
    if (!results || !results.report_file_encrypted) {
      return res.status(404).json({ success: false, error: 'No encrypted report found' });
    }

    // Decrypt PDF
    const kek = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    
    try {
      const encryptedBuffer = Buffer.from(results.report_file_encrypted, 'hex');
      const ivBuf = Buffer.from(results.report_file_iv, 'hex');
      const tagBuf = Buffer.from(results.report_file_tag, 'hex');

      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(kek, 'hex'), ivBuf);
      decipher.setAuthTag(tagBuf);
      const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

      // Update decryption metadata
      await db('lab_results').where('test_id', testId).update({
        encryption_status: 'decrypted',
        decrypted_at: new Date(),
        decrypted_by: userId
      });

      // Audit log
      await logAuditAction(db, {
        userId: userId,
        action: 'decrypted_report',
        resourceType: 'lab_report',
        resourceId: testId,
        status: 'success'
      });

      // Send file
      res.set('Content-Type', 'application/pdf');
      const filename = `lab-report-${test.test_name.replace(/[^a-z0-9-_\.]/gi, '_')}-${testId.substring(0, 8)}.pdf`;
      res.set('Content-Disposition', `attachment; filename="${filename}"`);
      return res.send(decrypted);

    } catch (err) {
      console.error('Decryption error:', err);
      return res.status(500).json({ success: false, error: 'Failed to decrypt report' });
    }

  } catch (error) {
    console.error('Decrypt endpoint error:', error);
    res.status(500).json({ success: false, error: 'Failed to decrypt report' });
  }
});

// ✅ 9. GET /api/lab/results/:testId/encryption-status - Check encryption status
router.get('/results/:testId/encryption-status', authenticate, requireRole(['doctor', 'lab_technician']), async (req, res) => {
  try {
    const db = req.app.get('db');
    const { testId } = req.params;

    const results = await db('lab_results').where('test_id', testId).first();
    
    if (!results) {
      return res.json({
        success: true,
        testId: testId,
        encryptionStatus: 'none',
        isEncrypted: false,
        message: 'No report found'
      });
    }

    res.json({
      success: true,
      testId: testId,
      encryptionStatus: results.encryption_status || 'none',
      isEncrypted: results.encryption_status === 'encrypted',
      encryptedAt: results.encrypted_at,
      encryptedBy: results.encrypted_by,
      decryptedAt: results.decrypted_at,
      decryptedBy: results.decrypted_by,
      message: results.encryption_status === 'encrypted' ? 'Report is encrypted' : 'Report is not encrypted'
    });

  } catch (error) {
    console.error('Encryption status error:', error);
    res.status(500).json({ success: false, error: 'Failed to get encryption status' });
  }
});

module.exports = router;
