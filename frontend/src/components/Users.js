import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchUsers } from '../api/test';
import { getCurrentUser } from '../api/userAPI';

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
    <>
      <h2>Users:</h2>
      <ul>
        {users.map(user => (
          <li key={user.uuid}>
            <Link to={`/user/${user.uuid}`}>{user.username}</Link>
          </li>
        ))}
      </ul>
    </>
  );
}

export default Users;
