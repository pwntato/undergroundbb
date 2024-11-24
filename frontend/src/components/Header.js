import React from 'react';
import { AppBar, Toolbar, Typography, Button } from '@mui/material';
import { Link } from 'react-router-dom';

const Header = () => {
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
        <Button color="inherit" component={Link} to="/login">
          Login
        </Button>
        <Button color="inherit" component={Link} to="/signup">
          Signup
        </Button>
      </Toolbar>
    </AppBar>
  );
};

export default Header;
