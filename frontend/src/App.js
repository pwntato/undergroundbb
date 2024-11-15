import React, { useEffect, useState } from 'react';
// import logo from './logo.svg';\
import './App.css';
import CreateUser from './components/CreateUser';
import Time from './components/Time';
import Users from './components/Users';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <Time />
        <Users />
        <CreateUser />
      </header>
    </div>
  );
}

export default App;
