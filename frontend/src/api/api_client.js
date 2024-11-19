import axios from 'axios';

const createApiClient = (baseURL) => {
  const client = axios.create({
    baseURL: process.env.REACT_APP_API_URL + baseURL,
    withCredentials: true
  });

  return async (url, method = 'GET', data = null) => {
    const response = await client({
      url,
      method,
      data
    });
    return response.data;
  };
};

export default createApiClient;
