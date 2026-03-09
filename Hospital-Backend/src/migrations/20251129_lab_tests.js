/**
 * src/migrations/20251129_lab_tests.js
 * Lab Technician Portal - Test Orders and Results
 */

exports.up = async function(knex) {
  // Test Orders Table
  if (!(await knex.schema.hasTable('lab_tests'))) {
    await knex.schema.createTable('lab_tests', table => {
      table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
      table.uuid('patient_id').notNullable().references('id').inTable('patients').onDelete('CASCADE');
      table.uuid('doctor_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.text('test_type').notNullable(); // CBC, Lipid Profile, ECG, etc.
      table.text('status').defaultTo('pending'); // pending, collected, completed, reported
      table.text('instructions').nullable();
      table.timestamp('ordered_at').defaultTo(knex.fn.now());
      table.timestamp('due_date').nullable();
      table.text('test_id_masked').unique(); // LT-10293 format for display
      table.timestamps(true, true);
    });
  }

  // Lab Samples Table
  await knex.schema.createTable('lab_samples', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('test_id').notNullable().references('id').inTable('lab_tests').onDelete('CASCADE');
    table.uuid('collected_by').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.text('barcode').nullable();
    table.text('sample_type').notNullable(); // Blood, Urine, Tissue, etc.
    table.text('notes').nullable();
    table.timestamp('collected_at').defaultTo(knex.fn.now());
    table.text('storage_location').nullable();
    table.timestamps(true, true);
  });

  // Lab Results Table (with encryption fields)
  await knex.schema.createTable('lab_results', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('test_id').notNullable().references('id').inTable('lab_tests').onDelete('CASCADE');
    table.uuid('sample_id').notNullable().references('id').inTable('lab_samples').onDelete('CASCADE');
    table.uuid('technician_id').notNullable().references('id').inTable('users').onDelete('CASCADE');

    // Result values (encrypted)
    table.text('result_values_encrypted').nullable(); // JSON object of test parameters
    table.text('result_values_iv').nullable();
    table.text('result_values_tag').nullable();

    // Result file (encrypted)
    table.text('report_file_encrypted').nullable(); // PDF binary data encrypted
    table.text('report_file_iv').nullable();
    table.text('report_file_tag').nullable();
    table.text('report_file_hash').nullable(); // SHA-256 for integrity
    table.text('report_file_mime_type').nullable(); // application/pdf, image/png, etc.

    // Technician notes (encrypted)
    table.text('technician_notes_encrypted').nullable();
    table.text('technician_notes_iv').nullable();
    table.text('technician_notes_tag').nullable();

    // DEK wrapping
    table.text('dek_encrypted_with_kek').nullable(); // Wrapped DEK for this result
    table.text('kek_version').defaultTo('v1'); // KMS version

    // Result metadata
    table.text('result_category').nullable(); // Normal, Abnormal, Critical
    table.text('reference_ranges').nullable(); // JSON reference ranges
    table.timestamp('completed_at').defaultTo(knex.fn.now());
    table.text('status').defaultTo('draft'); // draft, completed, reviewed, reported

    table.timestamps(true, true);
  });

  // Audit Logs for Lab Actions
  await knex.schema.createTable('lab_audit_logs', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.text('action').notNullable(); // viewed, uploaded, downloaded, modified
    table.text('resource_type').notNullable(); // test, sample, result
    table.uuid('resource_id').notNullable();
    table.text('resource_name').nullable(); // test type, patient name masked
    table.text('ip_address').nullable();
    table.text('user_agent').nullable();
    table.text('status').nullable(); // success, denied
    table.text('reason_denied').nullable(); // if status = denied
    table.text('details').nullable(); // Additional JSON data
    table.text('log_hash').nullable(); // SHA-256 for tamper detection
    table.timestamp('created_at').defaultTo(knex.fn.now());
  });

  // Indexes for performance
  // Indexes for performance (created conditionally below)

  // Only add indexes if the table exists
  if (await knex.schema.hasTable('lab_tests')) {
    if (await knex.schema.hasColumn('lab_tests', 'patient_id')) {
      await knex.schema.table('lab_tests', table => table.index(['patient_id']));
    }
    if (await knex.schema.hasColumn('lab_tests', 'doctor_id')) {
      await knex.schema.table('lab_tests', table => table.index(['doctor_id']));
    }
    if (await knex.schema.hasColumn('lab_tests', 'status')) {
      await knex.schema.table('lab_tests', table => table.index(['status']));
    }
    if (await knex.schema.hasColumn('lab_tests', 'ordered_at')) {
      await knex.schema.table('lab_tests', table => table.index(['ordered_at']));
    }
  }

  await knex.schema.table('lab_samples', table => {
    table.index(['test_id']);
    table.index(['collected_by']);
    table.index(['collected_at']);
  });

  await knex.schema.table('lab_results', table => {
    table.index(['test_id']);
    table.index(['technician_id']);
    table.index(['status']);
    table.index(['completed_at']);
  });

  await knex.schema.table('lab_audit_logs', table => {
    table.index(['user_id']);
    table.index(['resource_type']);
    table.index(['action']);
    table.index(['created_at']);
  });
};

exports.down = async function(knex) {
  await knex.schema.dropTableIfExists('lab_audit_logs');
  await knex.schema.dropTableIfExists('lab_results');
  await knex.schema.dropTableIfExists('lab_samples');
  await knex.schema.dropTableIfExists('lab_tests');
};
