import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Login from './pages/Login';
import CreateUser from './pages/CreateUser';
import Time from './components/Time';
import Users from './components/Users';
import User from './pages/User';

const AppRoutes = () => {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/create-user" element={<CreateUser />} />
        <Route path="/user/:uuid" element={<User />} />
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
