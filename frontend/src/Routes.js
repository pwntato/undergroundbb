import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Header from './components/Header';
import Login from './pages/Login';
import CreateUser from './pages/CreateUser';
import Time from './components/Time';
import Users from './components/Users';
import User from './pages/User';

const AppRoutes = () => {
  return (
    <Router future={{ v7_relativeSplatPath: true, v7_startTransition: true }}>
      <Header />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<CreateUser />} />
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
