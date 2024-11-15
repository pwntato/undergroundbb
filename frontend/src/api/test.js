import createApiClient from './api_client';

const client = createApiClient('/test');

export const fetchUsers = async () => {
  const data = await client('/users');
  return data;
};

export const fetchTime = async () => {
  const data = await client('/time');
  return data.now;
};
