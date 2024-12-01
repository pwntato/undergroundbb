import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Container, TextField, Button, Typography, Box, Alert } from '@mui/material';
import { inviteUserToGroup } from '../api/groupAPI';
import { getUserByUsername } from '../api/userAPI';
import { useUser } from '../contexts/UserContext';

const InviteUser = () => {
  const { uuid } = useParams();
  const { state } = useUser();
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleInviteUser = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');

    try {
      const user = await getUserByUsername(username);
      if (!user) {
        setError('User not found');
        return;
      }

      if (state.userRole !== 'admin' && state.userRole !== 'ambassador') {
        setError('You do not have permission to invite users');
        return;
      }

      await inviteUserToGroup(uuid, user.uuid);
      setSuccess('User invited successfully');
    } catch (error) {
      setError('Error inviting user');
    }
  };

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h5" sx={{ mb: 2 }}>
          Invite User
        </Typography>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {success && <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>}
        <Box component="form" onSubmit={handleInviteUser} sx={{ width: '100%' }}>
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
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            color="primary"
            sx={{ mt: 3, mb: 2 }}
          >
            Invite
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default InviteUser;
