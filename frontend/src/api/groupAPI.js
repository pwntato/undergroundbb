import createApiClient from './api_client';

const client = createApiClient('/api/groups');

export const createGroup = async (name, description) => {
  const data = await client('/create-group', 'POST', { name, description });
  return data;
};
