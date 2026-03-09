const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const MEK_B64 = process.env.DEMO_MEK_BASE64;
if (!MEK_B64) throw new Error('Set DEMO_MEK_BASE64 in .env');
const MEK = Buffer.from(MEK_B64, 'base64');
if (MEK.length !== 32) throw new Error('MEK must be 32 bytes');

const KMS_STORE_PATH = path.join(__dirname, 'storage', 'keys', 'kms_store.json');


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
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}


async function loadStore() {
    try {
        const raw = await fs.readFile(KMS_STORE_PATH, 'utf8');
        return JSON.parse(raw);
    } catch {
        return {}; 
    }
}

async function saveStore(store) {
    await fs.mkdir(path.dirname(KMS_STORE_PATH), { recursive: true });
    await fs.writeFile(KMS_STORE_PATH, JSON.stringify(store, null, 2));
}


async function createKey(fileId) {
    const store = await loadStore();
    if (store[fileId]) return getDEK(fileId); 

    const dek = genDEK();
    const { ciphertext: wrappedDEK, iv, tag } = aesGcmEncrypt(dek, MEK);

    store[fileId] = {
        wrappedDEK: wrappedDEK.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        createdAt: new Date().toISOString()
    };
    await saveStore(store);

    return dek;
}

async function getDEK(fileId) {
    const store = await loadStore();
    const entry = store[fileId];
    if (!entry) throw new Error(`No DEK found for fileId: ${fileId}`);

    const wrappedDEK = Buffer.from(entry.wrappedDEK, 'base64');
    const iv = Buffer.from(entry.iv, 'base64');
    const tag = Buffer.from(entry.tag, 'base64');
    const dek = aesGcmDecrypt({ ciphertext: wrappedDEK, iv, tag }, MEK);
    return dek;
}

async function rotateKey(fileId) {
    const store = await loadStore();
    const oldDEK = await getDEK(fileId);
    const newDEK = genDEK();
    const { ciphertext: wrappedDEK, iv, tag } = aesGcmEncrypt(newDEK, MEK);

    store[fileId] = {
        wrappedDEK: wrappedDEK.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        rotatedAt: new Date().toISOString()
    };
    await saveStore(store);

    return newDEK;
}


async function initKMS() {
    await fs.mkdir(path.dirname(KMS_STORE_PATH), { recursive: true });
    try {
        await fs.access(KMS_STORE_PATH);
    } catch {
        await saveStore({});
    }
    console.log(`✔ KMS initialized at ${KMS_STORE_PATH}`);
}

module.exports = {
    initKMS,
    createKey,
    getDEK,
    rotateKey,
    _internal: { aesGcmEncrypt, aesGcmDecrypt, genDEK, genIV }
};
