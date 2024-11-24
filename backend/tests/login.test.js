const { login, isLoggedIn } = require('../users/login');
const pool = require('../db');
const { createHash } = require('../cryptography/hash');
const { generateKeyPair } = require('../cryptography/rsa');
const { encrypt, decrypt } = require('../cryptography/aes');

jest.mock('../db', () => ({
  query: jest.fn(),
}));

const createMockResponse = () => {
  const res = {};
  res.cookie = jest.fn().mockReturnValue(res);
  res.status = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  return res;
};

describe('User Login', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  test('should log in a user with valid credentials', async () => {
    const username = 'testuser';
    const password = 'Password123!';
    const { salt, hash } = createHash(password);
    const { publicKey, privateKey } = generateKeyPair();
    const encryptedPrivateKey = encrypt(privateKey, hash);

    pool.query.mockResolvedValueOnce({
      rows: [
        {
          username,
          salt,
          public_key: publicKey,
          private_key: encryptedPrivateKey,
        },
      ],
    });

    const session = {};
    const res = createMockResponse();
    const result = await login(username, password, session, res);

    expect(result).toBe(true);
    const tokenCookie = res.cookie.mock.calls.find(call => call[0] === 'token');
    const token = Buffer.from(tokenCookie[1], 'base64');

    const decryptedSessionPrivateKey = decrypt(session.sessionPrivateKey, token);

    expect(decryptedSessionPrivateKey).toBe(privateKey);
  });

  test('should fail login with invalid username', async () => {
    pool.query.mockResolvedValueOnce({ rows: [] });

    const session = {};
    await expect(login('invaliduser', 'password123', session)).rejects.toThrow('Invalid username or password');
  });

  test('should fail login with invalid password', async () => {
    const username = 'testuser';
    const password = 'password123';
    const { salt, hash } = createHash(password);
    const { publicKey, privateKey } = generateKeyPair();
    const encryptedPrivateKey = encrypt(privateKey, hash);

    pool.query.mockResolvedValueOnce({
      rows: [
        {
          username,
          salt,
          public_key: publicKey,
          private_key: encryptedPrivateKey,
        },
      ],
    });

    const session = {};
    await expect(login(username, 'wrongpassword', session)).rejects.toThrow('Invalid username or password');
  });

  test('should fail login with invalid key pair', async () => {
    const username = 'testuser';
    const password = 'password123';
    const { salt, hash } = createHash(password);
    const { publicKey } = generateKeyPair();
    const { privateKey: differentPrivateKey } = generateKeyPair();
    const encryptedPrivateKey = encrypt(differentPrivateKey, hash);

    pool.query.mockResolvedValueOnce({
      rows: [
        {
          username,
          salt,
          public_key: publicKey,
          private_key: encryptedPrivateKey,
        },
      ],
    });

    const session = {};
    await expect(login(username, password, session)).rejects.toThrow('Invalid username or password');
  });

  test('should return true if user is logged in and key pair is valid', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const session = { privateKey: privateKey };
    const result = isLoggedIn(session);
    expect(result).toBe(true);
  });

  test('should return false if user is not logged in', () => {
    const session = {};
    const result = isLoggedIn(session);
    expect(result).toBe(false);
  });
});
