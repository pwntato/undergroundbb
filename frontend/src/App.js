import React, { useEffect, useState } from 'react';
// import logo from './logo.svg';\
import './App.css';
import Login from './components/Login';
import CreateUser from './components/CreateUser';
import Time from './components/Time';
import Users from './components/Users';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLogin = () => {
    setIsLoggedIn(true);
  };

  return (
    <div className="App">
      <header className="App-header">
        <Time />
        <Users />
        {isLoggedIn ? null : <CreateUser />}
        <Login onLogin={handleLogin} />
      </header>
    </div>
  );
}

export default App;
