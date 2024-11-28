exports.up = (pgm) => {
  pgm.renameColumn('groups', 'createdAt', 'created_at');
};

exports.down = (pgm) => {
  pgm.renameColumn('groups', 'created_at', 'createdAt');
};
