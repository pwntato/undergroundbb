import React, { useEffect, useState } from 'react';
import axios from 'axios';
import logo from './logo.svg';
import './App.css';

function App() {
  const [time, setTime] = useState('');

  useEffect(() => {
    axios.get('http://localhost:3000/')
      .then(response => {
        console.log(response.data);
        setTime(response.data.now);
      })
      .catch(error => {
        console.error('There was an error fetching the time!', error);
      });
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <p>
          What time is it? {time}
        </p>
      </header>
    </div>
  );
}

export default App;
