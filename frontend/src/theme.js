import { createTheme } from '@mui/material/styles';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2', // A shade of blue representing trust
    },
    secondary: {
      main: '#4caf50', // A shade of green representing growth and safety
    },
    background: {
      default: '#f5f5f5', // Light background for a clean look
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
