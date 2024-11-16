import React, { useState } from 'react';
import './App.css';
import Login from './components/Login';
import CreateUser from './components/CreateUser';
import Time from './components/Time';
import Users from './components/Users';
import Header from './components/Header';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [showLogin, setShowLogin] = useState(false);
  const [showSignup, setShowSignup] = useState(false);

  const handleLogin = (username) => {
    setIsLoggedIn(true);
    setUsername(username);
    setShowLogin(false);
    setShowSignup(false);
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setUsername('');
  };

  const handleShowLogin = () => {
    setShowLogin(true);
    setShowSignup(false);
  };

  const handleShowSignup = () => {
    setShowSignup(true);
    setShowLogin(false);
  };

  return (
    <div className="App">
      <Header
        isLoggedIn={isLoggedIn}
        username={username}
        onLogout={handleLogout}
        onShowLogin={handleShowLogin}
        onShowSignup={handleShowSignup}
      />
      <header className="App-header">
        {isLoggedIn ? (
          <>
            <Time />
            <Users />
          </>
        ) : showSignup ? (
          <CreateUser />
        ) : showLogin ? (
          <Login onLogin={handleLogin} />
        ) : (
          <>
            <Time />
            <Users />
          </>
        )}
      </header>
    </div>
  );
}

export default App;
