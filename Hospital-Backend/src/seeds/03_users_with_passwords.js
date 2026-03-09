/**
 * Seed file: Add users with proper bcrypt password hashes
 * Run with: npx knex seed:run --env development --specific 03_users_with_passwords.js
 */

const bcrypt = require('bcryptjs');

// Pre-hashed passwords for all 8 roles
// Password format: Role@123
const HASHED_PASSWORDS = {
  'admin@hospital.com': '$2b$10$cZCXdWLnnSWjvIiS3Jt8B.lDkVp913bao4UBT0zhfa2af9AdHJ1Ge', // Admin@123
  'doctor@hospital.com': '$2b$10$Bz3iRpp2QOXxIy26EApEe.8zQD.D6FvppFPrMMBwzDO9KMj5SXkzi', // Doctor@123
  'nurse@hospital.com': '$2b$10$9x/K24fmDUV4a1eGNMgPk.H9ymbB6wDEq3XZAyy1SiW80ipdznmBS', // Nurse@123
  'receptionist@hospital.com': '$2b$10$emsFYzcswxj0hcp0TtvcXOt7y0WihSQMuF4wepgfRbU1e5g0QWxvy', // Receptionist@123
  'labtech@hospital.com': '$2b$10$uoD5VtJC1l3Un55LNmAQTu9ofdMchR7eIgH4BTW8G8YJCLWze3eDy', // LabTech@123
  'pharmacist@hospital.com': '$2b$10$7/33zY8vdJfxEzkWGJWPuO8GDh8AsHz/.3aetXRXMKLQLC7MsTHDi', // Pharmacist@123
  'accountant@hospital.com': '$2b$10$kwkVpgPimkIvCsld5YWL..6LbhK4OE7uzI/vjhi9ed4UwgZKuLBsi', // Accountant@123
  'patient@hospital.com': '$2b$10$i6/iQzLVFgsyGzg9kD29Iuw8Nyl4VadSE2pLX.d3YMED7/QUX65IO' // Patient@123
};

exports.seed = async function(knex) {
  // Clear existing non-patient data in correct order (respecting foreign keys)
  // Note: we intentionally do NOT delete `patients` here to avoid accidental data wipes
  await knex('audit_logs').del();
  await knex('files').del();
  await knex('vitals').del();
  await knex('prescriptions').del();
  await knex('lab_tests').del();
  await knex('appointments').del();
  await knex('users').del();

  // Insert all users with password hashes
  await knex('users').insert([
    {
      id: '550e8400-e29b-41d4-a716-446655440001',
      name: 'Dr. John Smith',
      email: 'doctor@hospital.com',
      role: 'doctor',
      password_hash: HASHED_PASSWORDS['doctor@hospital.com'],
      mfa_enabled: true,
      mfa_secret: 'MU7EI4S3KI2SQKDWMEYCS4KEKBXHUNBMNUUUY5KLIQ3FQTJQKZ4Q',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440002',
      name: 'Dr. Sarah Admin',
      email: 'admin@hospital.com',
      role: 'admin',
      password_hash: HASHED_PASSWORDS['admin@hospital.com'],
      mfa_enabled: true,
      mfa_secret: 'PVSU22Z3OBIWIZKXF52GWNDHLJJUMMSJKJJFI7L2IVAS44CJF42Q',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440003',
      name: 'Nurse Emily Johnson',
      email: 'nurse@hospital.com',
      role: 'nurse',
      password_hash: HASHED_PASSWORDS['nurse@hospital.com'],
      mfa_enabled: true,
      mfa_secret: 'IJ5HAYSCGB5S42CHGAXHS532MEZCY5L2OZESS4CRFRICGN2OHM4Q',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440004',
      name: 'Lab Tech Rachel Wilson',
      email: 'labtech@hospital.com',
      role: 'lab_technician',
      password_hash: HASHED_PASSWORDS['labtech@hospital.com'],
      mfa_enabled: true,
      mfa_secret: 'MJSSSLCEHQ7XQ4JROY3TSJCUJJ5VCXKHNBWTCXS3MIUHA3JZJZOQ',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440005',
      name: 'Accountant Patricia Brown',
      email: 'accountant@hospital.com',
      role: 'accountant',
      password_hash: HASHED_PASSWORDS['accountant@hospital.com'],
      mfa_enabled: true,
      mfa_secret: 'IBSG27J4NN3HSZTQGY4SS2DMNRPEGJRZIJFW4423J5WDMUBFEVKA',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440006',
      name: 'Pharmacist David Lee',
      email: 'pharmacist@hospital.com',
      role: 'pharmacist',
      password_hash: HASHED_PASSWORDS['pharmacist@hospital.com'],
      mfa_enabled: true,
      mfa_secret: 'MJMHSWBDJ5JWG4JKOY7UQTTLJ5SCUZSIK4ZEWQLDG5AGEJCYI5SQ',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440007',
      name: 'Mike Reception',
      email: 'receptionist@hospital.com',
      role: 'receptionist',
      password_hash: HASHED_PASSWORDS['receptionist@hospital.com'],
      mfa_enabled: true,
      mfa_secret: 'ENXE2JCKKZXHOMJRMV2EEOTHINCDIYLOPJ6SYRDDIJUFOJD5PMZA',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440008',
      name: 'John Patient',
      email: 'patient@hospital.com',
      role: 'patient',
      password_hash: HASHED_PASSWORDS['patient@hospital.com'],
      mfa_enabled: false,
      created_at: new Date(),
      updated_at: new Date(),
    },
  ]);

  console.log('✓ All 8 users seeded with bcrypt password hashes');
};
