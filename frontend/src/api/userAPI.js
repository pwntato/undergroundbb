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

export const validatePassword = async (password) => {
  try {
    const data = await client('/validate-password', 'POST', { password });
    return { valid: true, message: data.message };
  } catch (error) {
    if (error.response && error.response.data && error.response.data.error) {
      return { valid: false, message: error.response.data.error };
    } else {
      return { valid: false, message: 'An unknown error occurred' };
    }
  }
};

export const loginUser = async (username, password) => {
  const data = await client('/login', 'POST', { username, password });
  return data;
};

export const getCurrentUser = async () => {
  try {
    const data = await client('/current-user');
    return data;
  } catch (error) {
    return null;
  }
};

export const getUserByUuid = async (uuid) => {
  const data = await client(`/user/${uuid}`);
  return data;
};

export const logoutUser = async () => {
  const data = await client('/logout', 'POST');
  return data;
};

export const updateUser = async (userData) => {
  const data = await client('/current-user', 'PUT', userData);
  return data;
};

export const changePassword = async (oldPassword, newPassword) => {
  const data = await client('/change-password', 'PUT', { oldPassword, newPassword });
  return data;
};
