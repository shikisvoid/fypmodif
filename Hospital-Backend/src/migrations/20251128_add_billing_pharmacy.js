/**
 * src/migrations/20251128_add_billing_pharmacy.js
 * Add billing, billing_services, and pharmacy inventory tables
 */
exports.up = async function(knex) {
  // billing table
  await knex.schema.createTable('billing', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('patient_id').references('id').inTable('patients').onDelete('CASCADE').notNullable();
    table.uuid('created_by').references('id').inTable('users').nullable(); // Admin/accountant who created bill
    table.date('bill_date').defaultTo(knex.fn.now());
    table.date('due_date').nullable();
    table.decimal('total_amount', 10, 2).defaultTo(0);
    table.decimal('amount_paid', 10, 2).defaultTo(0);
    table.decimal('discount', 10, 2).defaultTo(0);
    table.text('status').defaultTo('pending'); // pending, partial, paid, overdue
    table.text('payment_method').nullable(); // cash, card, check, insurance
    table.timestamp('payment_date').nullable();
    table.text('notes').nullable();
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // billing_services table (itemized services in each bill)
  await knex.schema.createTable('billing_services', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('billing_id').references('id').inTable('billing').onDelete('CASCADE').notNullable();
    table.text('service_name').notNullable(); // e.g., "CT Scan", "Consultation"
    table.text('description').nullable();
    table.decimal('amount', 10, 2).notNullable();
    table.integer('quantity').defaultTo(1);
    table.timestamp('created_at').defaultTo(knex.fn.now());
  });

  // pharmacy_inventory table
  await knex.schema.createTable('pharmacy_inventory', table => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.text('medicine_name').notNullable().unique();
    table.text('generic_name').nullable();
    table.text('category').nullable(); // antibiotics, pain relief, etc.
    table.integer('quantity_in_stock').defaultTo(0);
    table.integer('reorder_level').defaultTo(10);
    table.text('unit').defaultTo('tablets'); // tablets, ml, vials, etc.
    table.decimal('unit_price', 10, 2).notNullable();
    table.text('manufacturer').nullable();
    table.date('expiry_date').nullable();
    table.text('batch_number').nullable();
    table.text('storage_location').nullable();
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('updated_at').defaultTo(knex.fn.now());
  });

  // Enhance lab_tests table with result upload field
  if (await knex.schema.hasTable('lab_tests')) {
    const hasResultUrl = await knex.schema.hasColumn('lab_tests', 'result_file_url');
    if (!hasResultUrl) {
      await knex.schema.table('lab_tests', table => {
        table.text('result_file_url').nullable(); // URL to uploaded result file/PDF
      });
    }
  }
};

exports.down = async function(knex) {
  // Drop tables in reverse order of creation
  if (await knex.schema.hasTable('pharmacy_inventory')) {
    await knex.schema.dropTable('pharmacy_inventory');
  }
  if (await knex.schema.hasTable('billing_services')) {
    await knex.schema.dropTable('billing_services');
  }
  if (await knex.schema.hasTable('billing')) {
    await knex.schema.dropTable('billing');
  }

  // Remove added columns
  if (await knex.schema.hasTable('lab_tests')) {
    const hasResultUrl = await knex.schema.hasColumn('lab_tests', 'result_file_url');
    if (hasResultUrl) {
      await knex.schema.table('lab_tests', table => {
        table.dropColumn('result_file_url');
      });
    }
  }
};
