import React from 'react';
import { Container } from '@mui/material';
import { lightBlue } from '@mui/material/colors';
import Login from './components/Login';
import CreateUser from './components/CreateUser';
import Time from './components/Time';
import Users from './components/Users';

function App() {
  return (
    <React.StrictMode>
      <Container 
        sx={{ 
          bgcolor: lightBlue[500], 
          height: '100vh' 
        }}
      >
        <div className="App">
          <header className="App-header">
              <Time />
              <Users />
              <Login />
              <CreateUser />
          </header>
        </div>
      </Container>
    </React.StrictMode>
  );
}

export default App;
