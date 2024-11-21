import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getUserByUuid } from '../api/userAPI';

const User = () => {
  const { uuid } = useParams();
  const [user, setUser] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const fetchedUser = await getUserByUuid(uuid);
        setUser(fetchedUser);
      } catch (error) {
        setError('User not found');
      }
    };

    fetchUser();
  }, [uuid]);

  if (error) {
    return <div>{error}</div>;
  }

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h2>User Details</h2>
      <p>Username: {user.username}</p>
      <p>UUID: {user.uuid}</p>
    </div>
  );
};

export default User;
