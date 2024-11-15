import axios from 'axios';

const apiUrl = process.env.REACT_APP_API_URL;

const createApiClient = (basePath) => {
  return async (additionalPath, method = 'GET', body = null) => {
    const url = `${apiUrl}${basePath}${additionalPath}`;
    const config = {
      method,
      url,
      data: body,
    };

    try {
      const response = await axios(config);
      return response.data;
    } catch (error) {
      console.error(`There was an error with the request to ${url}!`, error);
      throw error;
    }
  };
};

export default createApiClient;