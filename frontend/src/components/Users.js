import React, { useEffect, useState } from 'react';
import { fetchUsers } from '../api/test';
import { getCurrentUser } from '../api/user';

function Users() {
  const [users, setUsers] = useState([]);
  const [currentUser, setCurrentUser] = useState({ username: '', uuid: '' });

  useEffect(() => {
    const getUsers = async () => {
      try {
        const fetchedUsers = await fetchUsers();
        setUsers(fetchedUsers);
      } catch (error) {
        console.error('There was an error fetching the users!', error);
      }
    };

    const fetchCurrentUser = async () => {
      try {
        const user = await getCurrentUser();
        setCurrentUser(user);
      } catch (error) {
        console.error('There was an error fetching the current user!', error);
      }
    };

    getUsers();
    fetchCurrentUser();
  }, []);

  return (
    <div>
    <h2>Current User:</h2>
    <p>Username: {currentUser.username}</p>
    <p>UUID: {currentUser.uuid}</p>
      <h2>Users:</h2>
      <ul>
        {users.map(user => (
          <li key={user.id}>{user.username}</li>
        ))}
      </ul>
    </div>
  );
}

export default Users;
