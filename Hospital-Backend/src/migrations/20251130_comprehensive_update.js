/**
 * Comprehensive migration for healthcare module updates
 * - Add new doctor accounts
 * - Update billing structure with doctor_fees, lab_fees, pharmacist_fees
 * - Add notifications table
 * - Update appointments with doctor response
 */

exports.up = async function(knex) {
  // Add columns to billing table for fee breakdown
  if (await knex.schema.hasTable('billing')) {
    const hasDoctorFees = await knex.schema.hasColumn('billing', 'doctor_fees');
    const hasLabFees = await knex.schema.hasColumn('billing', 'lab_fees');
    const hasPharmacistFees = await knex.schema.hasColumn('billing', 'pharmacist_fees');
    const hasLabTestId = await knex.schema.hasColumn('billing', 'lab_test_id');
    const hasPrescriptionId = await knex.schema.hasColumn('billing', 'prescription_id');
    
    if (!hasDoctorFees || !hasLabFees || !hasPharmacistFees || !hasLabTestId || !hasPrescriptionId) {
      await knex.schema.alterTable('billing', table => {
        if (!hasDoctorFees) table.decimal('doctor_fees', 10, 2).defaultTo(0);
        if (!hasLabFees) table.decimal('lab_fees', 10, 2).defaultTo(0);
        if (!hasPharmacistFees) table.decimal('pharmacist_fees', 10, 2).defaultTo(0);
        if (!hasLabTestId) table.uuid('lab_test_id').references('id').inTable('lab_tests').onDelete('SET NULL');
        if (!hasPrescriptionId) table.uuid('prescription_id').references('id').inTable('prescriptions').onDelete('SET NULL');
      });
    }
  }

  // Add columns to appointments for doctor response
  if (await knex.schema.hasTable('appointments')) {
    const hasDoctorResponse = await knex.schema.hasColumn('appointments', 'doctor_response');
    if (!hasDoctorResponse) {
      await knex.schema.alterTable('appointments', table => {
        table.text('doctor_response').defaultTo('pending'); // pending, accepted, rejected, reschedule_requested
        table.text('reschedule_reason');
        table.timestamp('response_at');
      });
    }
  }

  // Add lab_fees column to lab_tests
  if (await knex.schema.hasTable('lab_tests')) {
    const hasLabFees = await knex.schema.hasColumn('lab_tests', 'lab_fees');
    if (!hasLabFees) {
      await knex.schema.alterTable('lab_tests', table => {
        table.decimal('lab_fees', 10, 2).defaultTo(0);
        table.uuid('technician_id').references('id').inTable('users');
        table.text('priority').defaultTo('normal'); // normal, urgent
      });
    }
  }

  // Add fee column to prescriptions for pharmacist
  if (await knex.schema.hasTable('prescriptions')) {
    const hasPharmacistFees = await knex.schema.hasColumn('prescriptions', 'pharmacist_fees');
    if (!hasPharmacistFees) {
      await knex.schema.alterTable('prescriptions', table => {
        table.decimal('pharmacist_fees', 10, 2).defaultTo(0);
        table.uuid('dispensed_by').references('id').inTable('users');
        table.timestamp('dispensed_at');
      });
    }
  }

  // Add threshold/alert columns to pharmacy_inventory
  if (await knex.schema.hasTable('pharmacy_inventory')) {
    const hasAlertThreshold = await knex.schema.hasColumn('pharmacy_inventory', 'alert_threshold');
    if (!hasAlertThreshold) {
      await knex.schema.alterTable('pharmacy_inventory', table => {
        table.integer('alert_threshold').defaultTo(20);
        table.boolean('low_stock_alert').defaultTo(false);
      });
    }
  }

  // Create notifications table
  if (!(await knex.schema.hasTable('notifications'))) {
    await knex.schema.createTable('notifications', table => {
      table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
      table.uuid('user_id').references('id').inTable('users').onDelete('CASCADE');
      table.text('title').notNullable();
      table.text('message').notNullable();
      table.text('type').defaultTo('info'); // info, warning, success, error
      table.text('category').defaultTo('general'); // appointment, billing, lab, pharmacy
      table.uuid('related_id'); // ID of related entity
      table.text('related_type'); // appointment, billing, lab_test, prescription
      table.boolean('read').defaultTo(false);
      table.timestamp('created_at').defaultTo(knex.fn.now());
    });
  }

  // Update patients table - add insurance_id column if not exists
  const hasInsuranceId = await knex.schema.hasColumn('patients', 'insurance_id');
  if (!hasInsuranceId) {
    await knex.schema.alterTable('patients', table => {
      table.text('insurance_id');
      table.text('insurance_provider');
    });
  }

  console.log('✓ Migration 20251130_comprehensive_update completed');
};

exports.down = async function(knex) {
  // Drop notifications table
  if (await knex.schema.hasTable('notifications')) {
    await knex.schema.dropTableIfExists('notifications');
  }

  // Remove added columns
  if (await knex.schema.hasTable('billing')) {
    if (await knex.schema.hasColumn('billing', 'doctor_fees')) {
      await knex.schema.alterTable('billing', table => {
        table.dropColumn('doctor_fees');
        table.dropColumn('lab_fees');
        table.dropColumn('lab_test_id');
        table.dropColumn('prescription_id');
        table.dropColumn('pharmacist_fees');
      });
    }
  }

  if (await knex.schema.hasTable('appointments')) {
    if (await knex.schema.hasColumn('appointments', 'doctor_response')) {
      await knex.schema.alterTable('appointments', table => {
        table.dropColumn('doctor_response');
        table.dropColumn('reschedule_reason');
        table.dropColumn('response_at');
      });
    }
  }

  if (await knex.schema.hasTable('lab_tests')) {
    if (await knex.schema.hasColumn('lab_tests', 'lab_fees')) {
      await knex.schema.alterTable('lab_tests', table => {
        table.dropColumn('lab_fees');
        table.dropColumn('technician_id');
        table.dropColumn('priority');
      });
    }
  }

  if (await knex.schema.hasTable('prescriptions')) {
    if (await knex.schema.hasColumn('prescriptions', 'pharmacist_fees')) {
      await knex.schema.alterTable('prescriptions', table => {
        table.dropColumn('pharmacist_fees');
        table.dropColumn('dispensed_by');
        table.dropColumn('dispensed_at');
      });
    }
  }

  if (await knex.schema.hasTable('pharmacy_inventory')) {
    if (await knex.schema.hasColumn('pharmacy_inventory', 'alert_threshold')) {
      await knex.schema.alterTable('pharmacy_inventory', table => {
        table.dropColumn('alert_threshold');
        table.dropColumn('low_stock_alert');
      });
    }
  }
};

