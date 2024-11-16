const { isUsernameAvailable, createUser } = require('../users/create_user');
const pool = require('../db');

// Mock the pool module
jest.mock('../db', () => ({
  query: jest.fn(),
}));

describe('User Management', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  test('should check if username is available', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ count: '0' }] });
    const available = await isUsernameAvailable('newuser');
    expect(available).toBe(true);
  });

  test('should check if username is not available', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ count: '1' }] });
    const available = await isUsernameAvailable('existinguser');
    expect(available).toBe(false);
  });

  test('should create a new user', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ count: '0' }] });
    pool.query.mockResolvedValueOnce({ rows: [] });

    await createUser('newuser', 'Password123!');

    expect(pool.query).toHaveBeenCalledWith('SELECT COUNT(*) FROM users WHERE username = $1', ['newuser']);
    expect(pool.query).toHaveBeenCalledWith(
      'INSERT INTO users (username, email, public_key, private_key, salt) VALUES ($1, $2, $3, $4, $5)',
      expect.any(Array)
    );
  });

  test('should throw an error if username is already taken', async () => {
    pool.query.mockResolvedValueOnce({ rows: [{ count: '1' }] });

    await expect(createUser('existinguser', 'password123')).rejects.toThrow('Username is already taken');
  });
});
