import React, { useState } from 'react';
import { checkUsernameAvailability, validatePassword, createUser } from '../api/userAPI';

const CreateUser = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [usernameError, setUsernameError] = useState('');
  const [passwordError, setPasswordError] = useState('');

  const handleUsernameBlur = async () => {
    try {
      const available = await checkUsernameAvailability(username);
      if (!available) {
        setUsernameError('Username is not available');
      } else {
        setUsernameError('');
      }
    } catch (error) {
      console.error('Error checking username availability', error);
    }
  };

  const handleCreateUser = async () => {
    if (password !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    } else {
      setPasswordError('');
    }

    try {
      const { valid, message } = await validatePassword(password);
      if (!valid) {
        setPasswordError(message);
        return;
      } else {
        setPasswordError('');
      }
    } catch (error) {
      console.error('Error validating password', error);
      setPasswordError('An unknown error occurred');
      return;
    }

    if (usernameError) {
      return;
    }

    try {
      await createUser(username, password);
      alert('User created successfully');
    } catch (error) {
      console.error('Error creating user', error);
    }
  };

  return (
    <div>
      <h2>Create User</h2>
      <div>
        <label>Username:</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          onBlur={handleUsernameBlur}
        />
        {usernameError && <div style={{ color: 'red', fontSize: 'small' }}>{usernameError}</div>}
      </div>
      <div>
        <label>Password:</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <div>
        <label>Confirm Password:</label>
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
        />
        {passwordError && <div style={{ color: 'red', fontSize: 'small' }}>{passwordError}</div>}
      </div>
      <button onClick={handleCreateUser}>Create</button>
    </div>
  );
};

export default CreateUser;
