import React from 'react';
import { Container } from '@mui/material';
import { lightBlue } from '@mui/material/colors';
import AppRoutes from './Routes';

function App() {
  return (
    <React.StrictMode>
      <Container 
        sx={{ 
          bgcolor: lightBlue[500], 
          height: '100vh' 
        }}
      >
        <AppRoutes />
      </Container>
    </React.StrictMode>
  );
}

export default App;
