import React, { useEffect, useState } from 'react';
import { Typography, Box } from '@mui/material';
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
    <Box 
      sx={{
        display: 'flex',
        // flexDirection: 'column',
        // alignItems: 'center',
        // justifyContent: 'center',
        // height: '100vh',
      }}  
    >
      <Typography variant="h3" sx={{p: 1}}>What time is it? {time}</Typography>
    </Box>
  );
}

export default Time;
