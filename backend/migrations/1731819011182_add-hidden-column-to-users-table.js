exports.up = (pgm) => {
  pgm.addColumns('users', {
    hidden: { type: 'boolean', notNull: true, default: true }
  });
};
  
exports.down = (pgm) => {
  pgm.dropColumns('users', ['hidden']);
};
