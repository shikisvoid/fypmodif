
const fs = require('fs').promises;
const path = require('path');


const BASE_STORAGE = path.join(__dirname, 'storage');
const ENCRYPTED_DIR = path.join(BASE_STORAGE, 'encrypted');
const METADATA_DIR  = path.join(BASE_STORAGE, 'metadata');
const TEMP_DIR      = path.join(BASE_STORAGE, 'temp');


async function initStorage() {
    await Promise.all([
        fs.mkdir(ENCRYPTED_DIR, { recursive: true }),
        fs.mkdir(METADATA_DIR, { recursive: true }),
        fs.mkdir(TEMP_DIR, { recursive: true })
    ]);
    console.log('✔ Storage folders initialized:');
    console.log('   ' + ENCRYPTED_DIR);
    console.log('   ' + TEMP_DIR);
    console.log('   ' + METADATA_DIR);
}

function getStoragePaths(fileName) {
    const encPath = path.join(ENCRYPTED_DIR, fileName + '.enc');
    const metaPath = path.join(METADATA_DIR, fileName + '.meta.json');
    return { encPath, metaPath };
}

function getTempPath(fileName) {
    return path.join(TEMP_DIR, fileName + '_decrypted.txt');
}

async function moveEncryptedFile(srcPath, fileName) {
    const { encPath } = getStoragePaths(fileName);
    await fs.rename(srcPath, encPath);
    console.log(`Encrypted file moved to: ${encPath}`);
    return encPath;
}


async function moveMetadataFile(srcPath, fileName) {
    const { metaPath } = getStoragePaths(fileName);
    await fs.rename(srcPath, metaPath);
    console.log(`Metadata file moved to: ${metaPath}`);
    return metaPath;
}

module.exports = {
    initStorage,
    getStoragePaths,
    getTempPath,
    moveEncryptedFile,
    moveMetadataFile,
    ENCRYPTED_DIR,
    METADATA_DIR,
    TEMP_DIR
};
