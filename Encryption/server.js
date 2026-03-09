const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

const encryption = require('./encryption'); 
const storageManager = require('./storageManager');
const kms = require('./kms');

const app = express();
const PORT = process.env.PORT || 3000;


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

storageManager.initStorage();

const upload = multer({ dest: path.join(__dirname, 'storage', 'temp') });


app.post('/upload-encrypt', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const fileId = req.file.originalname;
    const tempPath = req.file.path;

    console.log(`Encrypting file: ${fileId}`);

    
    const encFileName = fileId + '.enc';
    const metaFileName = fileId + '.meta.json';
    await encryption.encryptFile(
      tempPath,
      path.join(storageManager.ENCRYPTED_DIR, encFileName),
      path.join(storageManager.METADATA_DIR, metaFileName)
    );

    console.log(`File encrypted: ${encFileName}`);
    console.log(`Metadata saved: ${metaFileName}`);

    
    await kms.createKey(fileId);
    console.log(`DEK stored in KMS for: ${fileId}`);

    
    await fs.unlink(tempPath);
    console.log(`Temp file deleted: ${tempPath}`);

    
    res.json({
      message: 'File encrypted and stored successfully',
      fileId,
      encryptedPath: path.join(storageManager.ENCRYPTED_DIR, encFileName),
      metadataPath: path.join(storageManager.METADATA_DIR, metaFileName)
    });

  } catch (err) {
    console.error('Error during encryption:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/decrypt-file', async (req, res) => {
  try {
    const { fileId, user } = req.body;
    if (!fileId || !user) {
      return res.status(400).json({ error: 'Missing fileId or user info' });
    }

    console.log(`Attempting to decrypt file: ${fileId} for user: ${user.name}`);

    
    function checkIAM(user) {
      return user.permissions.includes('canViewPatients');
    }
    function checkMFA(user) { return true; }
    function checkDevicePosture(user) { return true; }

    if (!checkIAM(user)) return res.status(403).json({ error: 'Access denied by IAM' });
    if (!checkMFA(user)) return res.status(403).json({ error: 'Access denied by MFA' });
    if (!checkDevicePosture(user)) return res.status(403).json({ error: 'Access denied by Device Posture' });

    
    const { encPath, metaPath } = storageManager.getStoragePaths(fileId);
    const tempPath = storageManager.getTempPath(fileId);

    
    const plain = await encryption.decryptFile(encPath, metaPath, tempPath);

    console.log(`✔ Decryption successful for: ${fileId}`);
    console.log(`Temporary file path: ${tempPath}`);

    function send_log(event, fileId, user, info = {}) {
      console.log(`[AUDIT] ${new Date().toISOString()} ${event} user=${user.id} file=${fileId} ${JSON.stringify(info)}`);
    }

    send_log('attempt_decrypt', fileId, user);
    send_log('decrypt_success', fileId, user, { tempPath });

    
    setTimeout(async () => {
      await fs.unlink(tempPath).catch(() => {});
      console.log(`Temporary file deleted: ${tempPath}`);
    }, 5000);

    
    res.json({
      message: 'File decrypted successfully',
      fileId,
      tempPath,
      content: plain.toString()
    });

  } catch (err) {
    console.error('Decryption failed:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.send('Encryption Module is running. Use POST /upload-encrypt to upload files.');
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
