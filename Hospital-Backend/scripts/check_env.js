// backend/scripts/check_env.js
require('dotenv').config();
const required = [
  'DATABASE_URL',
  'APP_ENC_KEY_BASE64',
  'JWKS_URI',
  'JWT_AUDIENCE',
  'JWT_ISSUER'
];

const placeholders = required.filter(k => !process.env[k] || process.env[k].startsWith('REPLACE_'));
const loaded = required.filter(k => process.env[k] && !process.env[k].startsWith('REPLACE_'));

console.log('✓ Node loaded .env successfully.');
console.log('\n✓ Loaded variables:', loaded);
if (placeholders.length) {
  console.log('⚠  Still has placeholders (need to fill):', placeholders);
}
console.log('\nDATABASE_URL (redacted) =>', process.env.DATABASE_URL.replace(/:\/\/[^:]+:[^@]+@/, '://[user]:[pass]@'));
console.log('APP_ENC_KEY_BASE64 present:', !!process.env.APP_ENC_KEY_BASE64);
