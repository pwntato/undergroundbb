import React, { useEffect, useState } from 'react';
import { AppBar, Toolbar, Typography, Button, Menu, MenuItem, Divider } from '@mui/material';
import { Link, useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import { getCurrentUser, logoutUser } from '../api/userAPI';

const Header = () => {
  const { state, dispatch } = useUser();
  const [anchorEl, setAnchorEl] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchCurrentUser = async () => {
      try {
        const user = await getCurrentUser();
        if (user) {
          dispatch({ type: 'LOGIN', payload: { username: user.username } });
          dispatch({ type: 'SET_GROUPS', payload: user.groups });
        }
      } catch (error) {
        console.error('Error fetching current user', error);
      }
    };

    fetchCurrentUser();
  }, [dispatch]);

  const handleLogout = async () => {
    await logoutUser();
    dispatch({ type: 'LOGOUT' });
  };

  const handleMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleGroupSelect = (group) => {
    dispatch({ type: 'SET_SELECTED_GROUP', payload: { name: group.name, uuid: group.uuid } });
    handleMenuClose();
  };

  const handleCreateGroup = () => {
    navigate('/create-group');
    handleMenuClose();
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          <Button color="inherit" component={Link} to="/" sx={{ textTransform: 'none', fontSize: '1.5rem' }}>
            TrustBoard
          </Button>
        </Typography>
        <Button
          color="inherit"
          component={Link}
          to="/donate"
          sx={{
            backgroundColor: '#4caf50',
            '&:hover': {
              backgroundColor: '#388e3c',
            },
            marginRight: 2,
          }}
        >
          Donate
        </Button>
        <Button color="inherit" component={Link} to="/about">
          About
        </Button>
        {state.isLoggedIn && (
          <>
            <Button color="inherit" onClick={handleMenuOpen}>
              {state.selectedGroup.name || 'Groups'}
            </Button>
            <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
              {state.groups && Object.values(state.groups).filter(group => group.uuid !== state.selectedGroup.uuid).map(group => (
                <MenuItem key={group.uuid} onClick={() => handleGroupSelect(group)}>
                  {group.name}
                </MenuItem>
)             )}
              <Divider />
              <MenuItem onClick={handleCreateGroup}>Create Group</MenuItem>
            </Menu>
            <Button color="inherit" component={Link} to="/profile">
              {state.username}
            </Button>
            <Button color="inherit" onClick={handleLogout}>
              Logout
            </Button>
          </>
        )}
        {!state.isLoggedIn && (
          <>
            <Button color="inherit" component={Link} to="/login">
              Login
            </Button>
            <Button color="inherit" component={Link} to="/signup">
              Signup
            </Button>
          </>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Header;
