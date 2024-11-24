import { createTheme } from '@mui/material/styles';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#4caf50',
    },
    background: {
      default: '#f5f5f5',
    },
  },
  typography: {
    fontFamily: 'Roboto, Arial, sans-serif',
    h1: {
      fontWeight: 700,
      fontSize: '2.5rem',
      color: '#1976d2',
    },
    h2: {
      fontWeight: 700,
      fontSize: '2rem',
      color: '#1976d2',
    },
    body1: {
      fontSize: '1rem',
      color: '#333',
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
        },
      },
    },
  },
});

export default theme;
