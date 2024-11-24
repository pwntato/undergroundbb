import React from 'react';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Container from '@mui/material/Container';
import AppRoutes from './Routes';
import theme from './theme';

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container sx={{ paddingLeft: 1, paddingRight: 1 }}>
        <AppRoutes />
      </Container>
    </ThemeProvider>
  );
}

export default App;
