import React from 'react';
import { Container, Link, Typography, Box } from '@mui/material';

const About = () => {
  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h4" sx={{ mb: 4 }}>
          About UndergroundBB
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Our Mission
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          Placeholder text about the mission of UndergroundBB. This section will describe the core values and objectives of the organization.
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Our Team
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          Placeholder text about the team behind UndergroundBB. This section will introduce the key members and their roles.
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Our Values
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          Placeholder text about the values of UndergroundBB. This section will highlight the principles that guide the organization.
        </Typography>
      </Box>

      <Box>
        <Typography component="p">
          <Link href="https://github.com/pwntato/undergroundbb" target="_blank" rel="noopener noreferrer">
            UndergroundBB
          </Link>
          {' by '}
          <Link href="https://www.linkedin.com/in/jimmy-hendrix-11a9931/" target="_blank" rel="noopener noreferrer">
            James Hendrix
          </Link>
          {' is licensed under '}
          <Link href="https://creativecommons.org/licenses/by-nc-sa/4.0/?ref=chooser-v1" target="_blank" rel="noopener noreferrer">
            Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International
            <Box component="span" sx={{ display: 'inline-block', ml: 1 }}>
              <img src="https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1" alt="" style={{ height: 22, verticalAlign: 'text-bottom' }} />
              <img src="https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1" alt="" style={{ height: 22, marginLeft: 3, verticalAlign: 'text-bottom' }} />
              <img src="https://mirrors.creativecommons.org/presskit/icons/nc.svg?ref=chooser-v1" alt="" style={{ height: 22, marginLeft: 3, verticalAlign: 'text-bottom' }} />
              <img src="https://mirrors.creativecommons.org/presskit/icons/sa.svg?ref=chooser-v1" alt="" style={{ height: 22, marginLeft: 3, verticalAlign: 'text-bottom' }} />
            </Box>
          </Link>
        </Typography>
      </Box>

    </Container>
  );
};

export default About;
