import React, { useState } from 'react';
import './App.css';
import Login from './components/Login';
import CreateUser from './components/CreateUser';
import Time from './components/Time';
import Users from './components/Users';

function App() {

  return (
    <div className="App">
      <header className="App-header">
          <Time />
          <Users />
          <Login />
          <CreateUser />
      </header>
    </div>
  );
}

export default App;
