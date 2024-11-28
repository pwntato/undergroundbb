exports.up = (pgm) => {
  pgm.addColumns("groups", {
    createdAt: {
      type: "timestamp",
      notNull: true,
      default: pgm.func("current_timestamp"),
    },
  });
};

exports.down = (pgm) => {
  pgm.dropColumns("groups", ["createdAt"]);
};
