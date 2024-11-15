import createApiClient from './api_client';

const client = createApiClient('/api/users');

export const checkUsernameAvailability = async (username) => {
  const data = await client(`/check-username/${username}`);
  return data.available;
};

export const createUser = async (username, password) => {
  const data = await client('/create-user', 'POST', { username, password });
  return data;
};
