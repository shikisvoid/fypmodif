const fs = require('fs').promises;
const path = require('path');
const storage = require('./storageManager');
const kms = require('./kms');
const encryption = require('./encryption');

async function rotateAllKeys() {
    console.log('--- Starting Key Rotation ---');

    
    const files = await fs.readdir(storage.METADATA_DIR);
    const metaFiles = files.filter(f => f.endsWith('.meta.json'));

    for (const metaFile of metaFiles) {
        try {
            const metaPath = path.join(storage.METADATA_DIR, metaFile);
            const metaRaw = await fs.readFile(metaPath, 'utf8');
            const meta = JSON.parse(metaRaw);
            const fileId = meta.fileName; 


            console.log(`\nRotating key for: ${fileId}`);

            
            const newDEK = await kms.rotateKey(fileId);

            
            const encPath = path.join(storage.ENCRYPTED_DIR, fileId + '.enc');
            const tempDecryptedPath = storage.getTempPath(fileId);
        
            const plain = await encryption.decryptFile(encPath, metaPath, tempDecryptedPath);
            
            const { ciphertext, iv, tag } = encryption._internal.aesGcmEncrypt(plain, newDEK);
            await fs.writeFile(encPath, ciphertext);

            
            meta.fileIV = iv.toString('base64');
            meta.fileTag = tag.toString('base64');
            meta.rotatedAt = new Date().toISOString();
            await fs.writeFile(metaPath, JSON.stringify(meta, null, 2));

            
            await fs.unlink(tempDecryptedPath);

            console.log(`Key rotation complete for: ${fileId}`);

        } catch (err) {
            console.error(`Failed to rotate key for ${metaFile}:`, err);
        }
    }

    console.log('\n--- Key Rotation Worker Finished ---');
}

module.exports = { rotateAllKeys };
