exports.up = (pgm) => {
  pgm.createTable('users', {
    id: { type: 'serial', primaryKey: true },
    username: { type: 'varchar(100)', notNull: true, unique: true },
    created_at: { type: 'timestamp', default: pgm.func('current_timestamp') },
    updated_at: { type: 'timestamp', default: pgm.func('current_timestamp') }
  });
};
  
exports.down = (pgm) => {
  pgm.dropTable('users');
};
