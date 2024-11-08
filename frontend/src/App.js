import React, { useEffect, useState } from 'react';
// import logo from './logo.svg';
import { fetchTime } from './api';
import './App.css';

function App() {
  const [time, setTime] = useState('');

  useEffect(() => {
    const getTime = async () => {
      const fetchedTime = await fetchTime();
      setTime(fetchedTime);
    };

    getTime();
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
