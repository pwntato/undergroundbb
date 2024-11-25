import React from 'react';
import { Container, Typography, Box } from '@mui/material';

const About = () => {
  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h4" sx={{ mb: 4 }}>
          About TrustBoard
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Our Mission
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          Placeholder text about the mission of TrustBoard. This section will describe the core values and objectives of the organization.
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Our Team
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          Placeholder text about the team behind TrustBoard. This section will introduce the key members and their roles.
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Our Values
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          Placeholder text about the values of TrustBoard. This section will highlight the principles that guide the organization.
        </Typography>
      </Box>
    </Container>
  );
};

export default About;
