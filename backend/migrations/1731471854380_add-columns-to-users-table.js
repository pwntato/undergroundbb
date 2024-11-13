exports.up = (pgm) => {
  pgm.addColumns('users', {
    email: { type: 'varchar(255)', notNull: false, unique: true },
    public_key: { type: 'text', notNull: true },
    private_key: { type: 'text', notNull: true },
    salt: { type: 'varchar(64)', notNull: true },
    bio: { type: 'text', notNull: false }
  });
};
  
exports.down = (pgm) => {
  pgm.dropColumns('users', ['email', 'public_key', 'private_key', 'salt', 'bio']);
};
