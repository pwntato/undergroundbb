const createApiClient = (baseURL) => {
  console.log('API_URL:', process.env.REACT_APP_API_URL);
  console.log('baseURL:', baseURL);
  const apiUrl = process.env.REACT_APP_API_URL + baseURL;

  return async (url, method = 'GET', data = null) => {
    console.log('url:', url);
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    };

    if (data) {
      options.body = JSON.stringify(data);
    }

    const response = await fetch(apiUrl + url, options);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  };
};

export default createApiClient;
