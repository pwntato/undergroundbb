const { encrypt, decrypt } = require('../cryptography/aes');
const { generateKeyPair } = require('../cryptography/rsa');
const { createHash } = require('../cryptography/hash');

describe('AES Encryption and Decryption', () => {
  const validSecretKeyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // 64-character hex string (32 bytes)
  const invalidSecretKeyHex = '0123456789abcdef'; // 16-character hex string (8 bytes)
  const message = 'Hello, World!';

  test('should encrypt and decrypt the message correctly with a valid key', () => {
    const encryptedMessage = encrypt(message, validSecretKeyHex);
    const decryptedMessage = decrypt(encryptedMessage, validSecretKeyHex);

    expect(decryptedMessage).toBe(message);
  });

  test('should throw an error if the key is not 32 bytes long during encryption', () => {
    expect(() => encrypt(message, invalidSecretKeyHex)).toThrow('Secret key must be 32 bytes long');
  });

  test('should throw an error if the key is not 32 bytes long during decryption', () => {
    const encryptedMessage = encrypt(message, validSecretKeyHex);
    expect(() => decrypt(encryptedMessage, invalidSecretKeyHex)).toThrow('Secret key must be 32 bytes long');
  });

  test('should return different ciphertext for different messages', () => {
    const message2 = 'Hello, Universe!';
    const encryptedMessage1 = encrypt(message, validSecretKeyHex);
    const encryptedMessage2 = encrypt(message2, validSecretKeyHex);

    expect(encryptedMessage1).not.toBe(encryptedMessage2);
  });

  test('should return different ciphertext for different keys', () => {
    const validSecretKeyHex2 = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
    const encryptedMessage1 = encrypt(message, validSecretKeyHex);
    const encryptedMessage2 = encrypt(message, validSecretKeyHex2);

    expect(encryptedMessage1).not.toBe(encryptedMessage2);
  });

  test('should encrypt and decrypt RSA private key using AES with hashed key', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const password = 'Password123!';
    const { hash } = createHash(password);

    const encryptedPrivateKey = encrypt(privateKey, hash);
    const decryptedPrivateKey = decrypt(encryptedPrivateKey, hash);

    expect(decryptedPrivateKey).toBe(privateKey);
  });
});
