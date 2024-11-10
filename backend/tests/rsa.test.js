const { generateKeyPair, encrypt, decrypt } = require('../cryptography/rsa');

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
});
