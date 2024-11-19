import createApiClient from './api_client';

const client = createApiClient('/test');

export const fetchUsers = async () => {
  const data = await client('/users');
  console.log('fetchUsers', data);
  return data;
};

export const fetchTime = async () => {
  const data = await client('/time');
  return data.now;
};
