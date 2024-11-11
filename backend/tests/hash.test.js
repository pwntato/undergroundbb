const { createHash } = require('../cryptography/hash');

describe('SHA-3-256 Hashing', () => {
  test('should create a valid SHA-3-256 hash', () => {
    const input = 'Hello, World!';
    const expectedHash = '1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef';
    const hash = createHash(input);
    expect(hash).toBe(expectedHash);
  });

  test('should create different hashes for different inputs', () => {
    const input1 = 'Hello, World!';
    const input2 = 'Hello, Universe!';
    const hash1 = createHash(input1);
    const hash2 = createHash(input2);
    expect(hash1).not.toBe(hash2);
  });

  test('should create the same hash for the same input', () => {
    const input = 'Hello, World!';
    const hash1 = createHash(input);
    const hash2 = createHash(input);
    expect(hash1).toBe(hash2);
  });
});
