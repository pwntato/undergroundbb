import React from 'react';
import { Container, Typography, Box, List, ListItem, ListItemText, Button } from '@mui/material';
import { Link } from 'react-router-dom';

const Home = () => {
  const mockGroups = [
    { id: 1, name: 'Group 1' },
    { id: 2, name: 'Group 2' },
    { id: 3, name: 'Group 3' },
  ];

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h4" sx={{ mb: 4 }}>
          Welcome to TrustBoard
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Your Groups
        </Typography>
        <List sx={{ width: '100%', bgcolor: 'background.paper', mb: 4 }}>
          {mockGroups.map(group => (
            <ListItem key={group.id}>
              <ListItemText primary={group.name} />
            </ListItem>
          ))}
        </List>
        <Button variant="contained" color="primary" component={Link} to="/search">
          Search for Users or Groups
        </Button>
      </Box>
    </Container>
  );
};

export default Home;
