// tests/aes.test.js
const { encrypt, decrypt } = require('../cryptography/aes');

describe('AES Encryption and Decryption', () => {
  const validSecretKey = 'my-secret-key-123456789012345678'; // Must be 32 bytes for AES-256
  const invalidSecretKey = 'short-key';
  const message = 'Hello, World!';

  test('should encrypt and decrypt the message correctly with a valid key', () => {
    const encryptedMessage = encrypt(message, validSecretKey);
    const decryptedMessage = decrypt(encryptedMessage, validSecretKey);

    expect(decryptedMessage).toBe(message);
  });

  test('should throw an error if the key is not 32 bytes long during encryption', () => {
    expect(() => encrypt(message, invalidSecretKey)).toThrow('Secret key must be 32 bytes long');
  });

  test('should throw an error if the key is not 32 bytes long during decryption', () => {
    const encryptedMessage = encrypt(message, validSecretKey);
    expect(() => decrypt(encryptedMessage, invalidSecretKey)).toThrow('Secret key must be 32 bytes long');
  });

  test('should return different ciphertext for different messages', () => {
    const message2 = 'Hello, Universe!';
    const encryptedMessage1 = encrypt(message, validSecretKey);
    const encryptedMessage2 = encrypt(message2, validSecretKey);

    expect(encryptedMessage1).not.toBe(encryptedMessage2);
  });

  test('should return different ciphertext for different keys', () => {
    const validSecretKey2 = 'another-secret-key-1234567890123';
    const encryptedMessage1 = encrypt(message, validSecretKey);
    const encryptedMessage2 = encrypt(message, validSecretKey2);

    expect(encryptedMessage1).not.toBe(encryptedMessage2);
  });
});
