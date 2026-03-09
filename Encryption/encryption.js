const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const MEK_B64 = process.env.DEMO_MEK_BASE64;
if (!MEK_B64) {
  console.warn('WARNING: DEMO_MEK_BASE64 not found in Encrption/.env. Encryption/Decryption will fail without it.');
}
const MEK = MEK_B64 ? Buffer.from(MEK_B64, 'base64') : null;
if (MEK && MEK.length !== 32) {
  throw new Error('DEMO_MEK_BASE64 must decode to 32 bytes (256 bits). Regenerate the key and update .env.');
}


function genDEK() { return crypto.randomBytes(32); }    
function genIV()  { return crypto.randomBytes(12); }     

function aesGcmEncrypt(plainBuf, key) {
  
  const iv = genIV();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, iv, tag };
}

function aesGcmDecrypt({ ciphertext, iv, tag }, key) {
 
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain;
}


async function encryptFile(inputPath, outEncPath, outMetaPath, options = {}) {
  if (!MEK) throw new Error('MEK not configured. Set DEMO_MEK_BASE64 in Encrption/.env');

  
  const fileBuf = await fs.readFile(inputPath);

  
  const dek = genDEK();

  
  const { ciphertext, iv: fileIV, tag: fileTag } = aesGcmEncrypt(fileBuf, dek);

  
  const { ciphertext: wrappedDEK, iv: dekIV, tag: dekTag } = aesGcmEncrypt(dek, MEK);


  const metadata = {
    fileName: path.basename(inputPath),
    algorithm: 'AES-256-GCM',
    dekWrapped: wrappedDEK.toString('base64'),
    dekWrappedIV: dekIV.toString('base64'),
    dekWrappedTag: dekTag.toString('base64'),
    fileIV: fileIV.toString('base64'),
    fileTag: fileTag.toString('base64'),
    createdAt: new Date().toISOString(),
   
    keyInfo: {
      keyType: 'symmetric-demo-mek',
      note: 'Demo MEK stored in .env (do not use this in production).'
    }
  };


  await fs.writeFile(outEncPath, ciphertext);
  await fs.writeFile(outMetaPath, JSON.stringify(metadata, null, 2), { encoding: 'utf8' });

  return { outEncPath, outMetaPath };
}


async function decryptFile(encPath, metaPath, outPlainPath) {
  if (!MEK) throw new Error('MEK not configured. Set DEMO_MEK_BASE64 in Encrption/.env');

 
  const [metaRaw, ciphertextBuf] = await Promise.all([
    fs.readFile(metaPath, 'utf8'),
    fs.readFile(encPath)
  ]);

  const meta = JSON.parse(metaRaw);

  const wrappedDEK = Buffer.from(meta.dekWrapped, 'base64');
  const wrappedIV  = Buffer.from(meta.dekWrappedIV, 'base64');
  const wrappedTag = Buffer.from(meta.dekWrappedTag, 'base64');

  let dek;
  try {
    dek = aesGcmDecrypt({ ciphertext: wrappedDEK, iv: wrappedIV, tag: wrappedTag }, MEK);
  } catch (err) {
    throw new Error('Failed to unwrap DEK with MEK: ' + err.message);
  }

 
  const fileIV = Buffer.from(meta.fileIV, 'base64');
  const fileTag = Buffer.from(meta.fileTag, 'base64');

  let plain;
  try {
    plain = aesGcmDecrypt({ ciphertext: ciphertextBuf, iv: fileIV, tag: fileTag }, dek);
  } catch (err) {
    throw new Error('Failed to decrypt file (auth tag mismatch or corrupted): ' + err.message);
  }

  if (outPlainPath) {
    await fs.writeFile(outPlainPath, plain);
  }
  return plain;
}


module.exports = {
  encryptFile,
  decryptFile,
  _internal: { aesGcmEncrypt, aesGcmDecrypt, genDEK, genIV }
};
