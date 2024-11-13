import axios from 'axios';

const apiUrl = process.env.REACT_APP_API_URL;

export const fetchFromApi = async (endpoint) => {
  try {
    const response = await axios.get(`${apiUrl}${endpoint}`);
    return response.data;
  } catch (error) {
    console.error(`There was an error fetching data from ${endpoint}!`, error);
    throw error;
  }
};

export const fetchUsers = async () => {
  const data = await fetchFromApi('/test/users');
  return data;
};

export const fetchTime = async () => {
  const data = await fetchFromApi('/test/time');
  return data.now;
};
