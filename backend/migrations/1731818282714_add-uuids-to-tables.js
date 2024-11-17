exports.up = (pgm) => {
  // Add UUID column to groups table
  pgm.addColumns('groups', {
    uuid: { type: 'uuid', default: pgm.func('gen_random_uuid()'), notNull: true, unique: true }
  });
  
  // Add UUID column to posts table
  pgm.addColumns('posts', {
    uuid: { type: 'uuid', default: pgm.func('gen_random_uuid()'), notNull: true, unique: true }
  });
  
   // Add UUID column to users table
   pgm.addColumns('users', {
    uuid: { type: 'uuid', default: pgm.func('gen_random_uuid()'), notNull: true, unique: true }
  });
};
  
exports.down = (pgm) => {
  // Remove UUID column from groups table
  pgm.dropColumns('groups', ['uuid']);
  
  // Remove UUID column from posts table
  pgm.dropColumns('posts', ['uuid']);
  
  // Remove UUID column from users table
  pgm.dropColumns('users', ['uuid']);
};
