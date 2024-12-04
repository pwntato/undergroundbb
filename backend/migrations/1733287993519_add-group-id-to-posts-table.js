exports.up = (pgm) => {
  pgm.addColumns('posts', {
    group_id: {
      type: 'integer',
      notNull: true,
      references: 'groups(id)',
      onDelete: 'CASCADE'
    }
  });

  pgm.createIndex('posts', 'group_id');
};

exports.down = (pgm) => {
  pgm.dropIndex('posts', 'group_id');
  pgm.dropColumns('posts', ['group_id']);
};
