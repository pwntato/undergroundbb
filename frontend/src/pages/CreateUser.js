import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { checkUsernameAvailability, validatePassword, createUser } from '../api/userAPI';
import { Container, TextField, Button, Typography, Box, Alert } from '@mui/material';

const CreateUser = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [usernameError, setUsernameError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [generalError, setGeneralError] = useState('');
  const navigate = useNavigate();

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

  const handleConfirmPasswordBlur = () => {
    if (password !== confirmPassword) {
      setPasswordError('Passwords do not match');
    } else {
      setPasswordError('');
    }
  };

  const handleCreateUser = async (event) => {
    event.preventDefault();
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
      navigate('/login');
    } catch (error) {
      console.error('Error creating user', error);
      setGeneralError('Error creating user');
    }
  };

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h5" sx={{ mb: 2 }}>
          Create User
        </Typography>
        {generalError && <Alert severity="error" sx={{ mb: 2 }}>{generalError}</Alert>}
        <Box component="form" onSubmit={handleCreateUser} sx={{ width: '100%' }}>
          <TextField
            variant="outlined"
            margin="normal"
            required
            fullWidth
            id="username"
            label="Username"
            name="username"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onBlur={handleUsernameBlur}
            error={!!usernameError}
            helperText={usernameError}
          />
          <TextField
            variant="outlined"
            margin="normal"
            required
            fullWidth
            name="password"
            label="Password"
            type="password"
            id="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={!!passwordError}
            helperText={passwordError}
          />
          <TextField
            variant="outlined"
            margin="normal"
            required
            fullWidth
            name="confirmPassword"
            label="Confirm Password"
            type="password"
            id="confirmPassword"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            onBlur={handleConfirmPasswordBlur}
            error={!!passwordError}
            helperText={passwordError}
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            color="primary"
            sx={{ mt: 3, mb: 2 }}
          >
            Create
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default CreateUser;
