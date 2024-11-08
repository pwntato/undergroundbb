import React, { useEffect, useState } from 'react';
import axios from 'axios';
import logo from './logo.svg';
import './App.css';

function App() {
  const [time, setTime] = useState('');
  const apiUrl = process.env.REACT_APP_API_URL;

  useEffect(() => {
    axios.get(`${apiUrl}`)
      .then(response => {
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
