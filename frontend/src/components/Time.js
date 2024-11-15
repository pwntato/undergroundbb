import React, { useEffect, useState } from 'react';
import { fetchTime } from '../api/test';

function Time() {
  const [time, setTime] = useState('');

  useEffect(() => {
    const getTime = async () => {
      try {
        const fetchedTime = await fetchTime();
        setTime(fetchedTime);
      } catch (error) {
        console.error('There was an error fetching the time!', error);
      }
    };

    getTime();
  }, []);

  return (
    <p>
      What time is it? {time}
    </p>
  );
}

export default Time;
