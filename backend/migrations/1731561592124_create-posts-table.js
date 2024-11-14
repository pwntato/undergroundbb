exports.up = (pgm) => {
  pgm.createTable('posts', {
    id: { type: 'serial', primaryKey: true },
    title: { type: 'varchar(255)', notNull: false },
    body: { type: 'text', notNull: true },
    creator_id: { type: 'integer', notNull: true, references: 'users(id)', onDelete: 'CASCADE' },
    created_at: { type: 'timestamp', notNull: true, default: pgm.func('current_timestamp') },
    last_edited: { type: 'timestamp', notNull: true, default: pgm.func('current_timestamp') },
    parent_post_id: { type: 'integer', references: 'posts(id)', onDelete: 'SET NULL' },
    pinned: { type: 'boolean', notNull: true, default: false }
  });
  
  pgm.createIndex('posts', 'creator_id');
  pgm.createIndex('posts', 'parent_post_id');
};
  
exports.down = (pgm) => {
  pgm.dropTable('posts');
};
