const { createHash, verifyHash } = require('../cryptography/hash');

describe('SHA-3-256 Hashing with Salt', () => {
  test('should create a valid SHA-3-256 hash with a salt', () => {
    const input = 'Hello, World!';
    const { salt, hash } = createHash(input);
    expect(salt).toBeDefined();
    expect(hash).toBeDefined();
  });

  test('should create different hashes for different inputs', () => {
    const input1 = 'Hello, World!';
    const input2 = 'Hello, Universe!';
    const { hash: hash1 } = createHash(input1);
    const { hash: hash2 } = createHash(input2);
    expect(hash1).not.toBe(hash2);
  });

  test('should create different hashes for the same input with different salts', () => {
    const input = 'Hello, World!';
    const { hash: hash1 } = createHash(input);
    const { hash: hash2 } = createHash(input);
    expect(hash1).not.toBe(hash2);
  });

  test('should verify the hash correctly', () => {
    const input = 'Hello, World!';
    const { salt, hash } = createHash(input);
    const isValid = verifyHash(input, salt, hash);
    expect(isValid).toBe(true);
  });

  test('should fail verification for incorrect input', () => {
    const input = 'Hello, World!';
    const incorrectInput = 'Hello, Universe!';
    const { salt, hash } = createHash(input);
    const isValid = verifyHash(incorrectInput, salt, hash);
    expect(isValid).toBe(false);
  });
});
