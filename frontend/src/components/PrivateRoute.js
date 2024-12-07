import React, { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import { getCurrentUser } from '../api/userAPI';

const PrivateRoute = ({ children }) => {
  const { state, dispatch } = useUser();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const user = await getCurrentUser();
        if (user) {
          dispatch({ type: 'LOGIN', payload: { username: user.username } });
          dispatch({ type: 'SET_GROUPS', payload: user.groups });
        }
      } catch (error) {
        console.error('Error fetching current user', error);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [dispatch]);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!state.isLoggedIn) {
    return <Navigate to="/login" />;
  }

  return children;
};

export default PrivateRoute;
