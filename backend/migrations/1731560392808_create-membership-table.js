exports.up = (pgm) => {
  pgm.createTable('membership', {
    id: { type: 'serial', primaryKey: true },
    role: { type: 'varchar(255)', notNull: true },
    encrypted_group_key: { type: 'text', notNull: true },
    invited_by: { type: 'integer', references: 'users(id)', onDelete: 'SET NULL' },
    user_id: { type: 'integer', notNull: true, references: 'users(id)', onDelete: 'CASCADE' },
    group_id: { type: 'integer', notNull: true, references: 'groups(id)', onDelete: 'CASCADE' }
  });
  
  pgm.createIndex('membership', 'invited_by');
  pgm.createIndex('membership', 'user_id');
  pgm.createIndex('membership', 'group_id');
};
  
exports.down = (pgm) => {
  pgm.dropTable('membership');
};
  