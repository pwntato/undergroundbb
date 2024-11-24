import React from 'react';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Container } from '@mui/material';
import AppRoutes from './Routes';
import theme from './theme';

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container 
        sx={{ 
          height: '100vh' 
        }}
      >
        <AppRoutes />
      </Container>
    </ThemeProvider>
  );
}

export default App;
