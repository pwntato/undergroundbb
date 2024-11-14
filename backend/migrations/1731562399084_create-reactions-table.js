exports.up = (pgm) => {
  pgm.createTable('reactions', {
    id: { type: 'serial', primaryKey: true },
    reaction_type: { type: 'varchar(255)', notNull: true },
    created_at: { type: 'timestamp', notNull: true, default: pgm.func('current_timestamp') },
    user_id: { type: 'integer', notNull: true, references: 'users(id)', onDelete: 'CASCADE' },
    post_id: { type: 'integer', notNull: true, references: 'posts(id)', onDelete: 'CASCADE' }
  });
  
  pgm.createIndex('reactions', 'user_id');
  pgm.createIndex('reactions', 'post_id');
};
  
exports.down = (pgm) => {
  pgm.dropTable('reactions');
};
