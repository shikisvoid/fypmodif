/**
 * src/migrations/20251201_add_encryption_status.js
 * Add encryption_status and related encryption tracking columns to lab_results
 */

exports.up = async function(knex) {
  // Check if lab_results table exists
  if (await knex.schema.hasTable('lab_results')) {
    // Check if encryption_status column already exists
    const hasEncryptionStatus = await knex.schema.hasColumn('lab_results', 'encryption_status');
    
    if (!hasEncryptionStatus) {
      await knex.schema.table('lab_results', table => {
        // Encryption tracking columns
        table.text('encryption_status').nullable().defaultTo('none'); // 'none', 'encrypted', 'decrypted'
        table.timestamp('encrypted_at').nullable(); // When encryption happened
        table.uuid('encrypted_by').nullable().references('id').inTable('users').onDelete('SET NULL'); // Who encrypted it
        table.timestamp('decrypted_at').nullable(); // When decryption happened
        table.uuid('decrypted_by').nullable().references('id').inTable('users').onDelete('SET NULL'); // Who decrypted it
      });
    }
  }
};

exports.down = async function(knex) {
  if (await knex.schema.hasTable('lab_results')) {
    const hasEncryptionStatus = await knex.schema.hasColumn('lab_results', 'encryption_status');
    
    if (hasEncryptionStatus) {
      await knex.schema.table('lab_results', table => {
        table.dropColumn('encryption_status');
        table.dropColumn('encrypted_at');
        table.dropColumn('encrypted_by');
        table.dropColumn('decrypted_at');
        table.dropColumn('decrypted_by');
      });
    }
  }
};
