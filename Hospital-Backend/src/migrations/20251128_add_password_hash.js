/**
 * src/migrations/20251128_add_password_hash.js
 * Add password_hash column to users table
 */
exports.up = async function(knex) {
  return knex.schema.table('users', table => {
    table.text('password_hash').nullable(); // Store bcrypt hashed passwords
  });
};

exports.down = async function(knex) {
  return knex.schema.table('users', table => {
    table.dropColumn('password_hash');
  });
};
