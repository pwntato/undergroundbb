exports.up = (pgm) => {
  pgm.addColumns("users", {
    last_login: {
      type: "timestamp",
      notNull: true,
      default: pgm.func("current_timestamp"),
    },
  });
};

exports.down = (pgm) => {
  pgm.dropColumns("users", ["last_login"]);
};
