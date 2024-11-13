const { generateKeyPair, encrypt, decrypt, verifyKeyPair } = require('../cryptography/rsa');

describe('RSA-3072 Key Generation, Encryption, and Decryption', () => {
  test('should generate a valid RSA key pair', () => {
    const { publicKey, privateKey } = generateKeyPair();
    expect(publicKey).toBeDefined();
    expect(privateKey).toBeDefined();
  });

  test('should encrypt and decrypt the message correctly', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const message = 'Hello, World!';
    const encryptedMessage = encrypt(message, publicKey);
    const decryptedMessage = decrypt(encryptedMessage, privateKey);

    expect(decryptedMessage).toBe(message);
  });

  test('should fail decryption with a different private key', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const { privateKey: differentPrivateKey } = generateKeyPair();
    const message = 'Hello, World!';
    const encryptedMessage = encrypt(message, publicKey);

    expect(() => {
      decrypt(encryptedMessage, differentPrivateKey);
    }).toThrow();
  });

  test('should verify that the public and private keys are part of the same key pair', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const isValidKeyPair = verifyKeyPair(publicKey, privateKey);
    expect(isValidKeyPair).toBe(true);
  });

  test('should fail verification for mismatched public and private keys', () => {
    const { publicKey } = generateKeyPair();
    const { privateKey: differentPrivateKey } = generateKeyPair();
    const isValidKeyPair = verifyKeyPair(publicKey, differentPrivateKey);
    expect(isValidKeyPair).toBe(false);
  });
});
