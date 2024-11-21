import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Login from './pages/Login';
import CreateUser from './pages/CreateUser';
import Time from './components/Time';
import Users from './components/Users';

const AppRoutes = () => {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/create-user" element={<CreateUser />} />
        <Route path="/" element={
          <>
            <Time />
            <Users />
          </>
        } />
      </Routes>
    </Router>
  );
};

export default AppRoutes;
