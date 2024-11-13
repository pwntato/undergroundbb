import React, { useEffect, useState } from 'react';
import { fetchUsers } from '../api';

function Users() {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    const getUsers = async () => {
      try {
        const fetchedUsers = await fetchUsers();
        setUsers(fetchedUsers);
      } catch (error) {
        console.error('There was an error fetching the users!', error);
      }
    };

    getUsers();
  }, []);

  return (
    <div>
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
