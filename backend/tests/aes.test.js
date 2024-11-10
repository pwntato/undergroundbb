const { encrypt, decrypt } = require('../cryptography/aes');

describe('AES Encryption and Decryption', () => {
  const secretKey = 'my-secret-key-1234567890123456'; // Must be 32 bytes for AES-256
  const message = 'Hello, World!';

  test('should encrypt and decrypt the message correctly', () => {
    const encryptedMessage = encrypt(message, secretKey);
    const decryptedMessage = decrypt(encryptedMessage, secretKey);

    expect(decryptedMessage).toBe(message);
  });

  test('should return different ciphertext for different messages', () => {
    const message2 = 'Hello, Universe!';
    const encryptedMessage1 = encrypt(message, secretKey);
    const encryptedMessage2 = encrypt(message2, secretKey);

    expect(encryptedMessage1).not.toBe(encryptedMessage2);
  });

  test('should return different ciphertext for different keys', () => {
    const secretKey2 = 'another-secret-key-1234567890123456';
    const encryptedMessage1 = encrypt(message, secretKey);
    const encryptedMessage2 = encrypt(message, secretKey2);

    expect(encryptedMessage1).not.toBe(encryptedMessage2);
  });
});
