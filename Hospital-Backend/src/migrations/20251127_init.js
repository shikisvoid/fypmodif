/**
 * src/migrations/20251127_init.js
 * Initial database schema with core tables
 */
exports.up = async function(knex) {
  // Enable uuid extension (uuid-ossp) for uuid_generate_v4()
  await knex.raw('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";');

  // users table (local metadata + JWT/IdP sync)
  await knex.schema.createTable('users', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.text('external_id').nullable().unique().index(); // IdP subject (optional if using self-hosted JWT)
    table.text('name').notNullable();
    table.text('email').notNullable().unique();
    table.text('role').notNullable(); // doctor, nurse, admin, patient, lab, pharmacist
    table.text('department').nullable();
    table.text('mfa_enabled').defaultTo('false'); // '0' or '1'
    table.text('mfa_secret').nullable(); // TOTP secret (encrypted in production)
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // patients
  await knex.schema.createTable('patients', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.text('mrn').unique().nullable(); // Medical Record Number
    table.text('first_name').notNullable();
    table.text('last_name').notNullable();
    table.date('dob').nullable();
    table.text('gender').nullable();
    table.jsonb('contact').nullable(); // { phone, address, etc. }
    table.jsonb('insurance').nullable(); // { provider, policy_number, etc. }
    table.jsonb('allergies').nullable(); // [{ name, severity }, ...]
    table.jsonb('medical_history').nullable();
    table.jsonb('metadata').nullable(); // custom fields
    table.text('emergency_contact').nullable();
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // appointments
  await knex.schema.createTable('appointments', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('patient_id').references('id').inTable('patients').onDelete('CASCADE');
    table.uuid('doctor_id').references('id').inTable('users').nullable();
    table.timestamp('scheduled_at').notNullable();
    table.text('status').defaultTo('scheduled'); // scheduled, completed, cancelled
    table.text('appointment_type').nullable(); // consultation, follow-up, lab, etc.
    table.text('notes').nullable();
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // lab_tests
  await knex.schema.createTable('lab_tests', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('patient_id').references('id').inTable('patients').onDelete('CASCADE');
    table.uuid('requested_by').references('id').inTable('users').nullable();
    table.text('test_name').notNullable();
    table.text('status').defaultTo('pending'); // pending, completed, reviewed
    table.jsonb('result_data').nullable(); // test results as JSON
    table.text('result_pdf_key').nullable(); // S3/MinIO storage key for PDF
    table.text('notes').nullable();
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('completed_at').nullable();
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // prescriptions
  await knex.schema.createTable('prescriptions', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('patient_id').references('id').inTable('patients').onDelete('CASCADE');
    table.uuid('prescribed_by').references('id').inTable('users').nullable();
    table.jsonb('meds').notNullable(); // [{ name, dosage, frequency, duration }, ...]
    table.text('notes').nullable();
    table.text('status').defaultTo('active'); // active, inactive, expired
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // vitals (blood pressure, heart rate, temperature, etc.)
  await knex.schema.createTable('vitals', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('patient_id').references('id').inTable('patients').onDelete('CASCADE');
    table.uuid('recorded_by').references('id').inTable('users').nullable();
    table.timestamp('recorded_at').defaultTo(knex.fn.now());
    table.jsonb('metrics').notNullable(); // { bp_systolic, bp_diastolic, heart_rate, temp, weight, height, etc. }
    table.timestamp('created_at').defaultTo(knex.fn.now());
  });

  // files (PDFs, documents, reports)
  await knex.schema.createTable('files', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('owner_patient_id').references('id').inTable('patients').onDelete('CASCADE').nullable();
    table.uuid('uploaded_by').references('id').inTable('users').nullable();
    table.text('storage_key').notNullable(); // S3/MinIO key
    table.text('filename').notNullable();
    table.text('mime').notNullable();
    table.bigInteger('size_bytes').nullable();
    table.text('checksum').nullable(); // SHA-256 for integrity
    table.text('encryption_algorithm').nullable(); // e.g., AES-256-GCM
    table.text('file_type').nullable(); // lab-result, prescription, medical-record, etc.
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // audit_logs (for HIPAA compliance)
  await knex.schema.createTable('audit_logs', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('actor_id').references('id').inTable('users').onDelete('SET NULL').nullable();
    table.text('action').notNullable(); // READ, CREATE, UPDATE, DELETE, EXPORT, etc.
    table.text('resource_type').notNullable(); // patient, lab_test, file, etc.
    table.uuid('resource_id').nullable();
    table.jsonb('details').nullable(); // what changed, old_value, new_value, etc.
    table.specificType('remote_addr', 'inet').nullable();
    table.text('user_agent').nullable();
    table.text('status').defaultTo('success'); // success, failure
    table.timestamp('created_at').defaultTo(knex.fn.now());
  });
};

exports.down = async function(knex) {
  await knex.schema.dropTableIfExists('audit_logs');
  await knex.schema.dropTableIfExists('files');
  await knex.schema.dropTableIfExists('vitals');
  await knex.schema.dropTableIfExists('prescriptions');
  await knex.schema.dropTableIfExists('lab_tests');
  await knex.schema.dropTableIfExists('appointments');
  await knex.schema.dropTableIfExists('patients');
  await knex.schema.dropTableIfExists('users');
};
