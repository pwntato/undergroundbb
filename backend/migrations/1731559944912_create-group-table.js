exports.up = (pgm) => {
  pgm.createTable('group', {
    id: { type: 'serial', primaryKey: true },
    name: { type: 'varchar(255)', notNull: true },
    description: { type: 'text', notNull: false },
    hidden: { type: 'boolean', notNull: true, default: true },
    trust_trace: { type: 'boolean', notNull: true, default: false }
  });
};
  
exports.down = (pgm) => {
  pgm.dropTable('group');
};
