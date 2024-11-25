import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Header from './components/Header';
import Login from './pages/Login';
import CreateUser from './pages/CreateUser';
import User from './pages/User';
import Home from './pages/Home';
import About from './pages/About';
import Profile from './pages/Profile';
import { useUser } from './contexts/UserContext';

const AppRoutes = () => {
  const { state } = useUser();

  return (
    <Router future={{ v7_relativeSplatPath: true, v7_startTransition: true }}>
      <Header />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<CreateUser />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/user/:uuid" element={<User />} />
        <Route path="/" element={state.isLoggedIn ? <Home /> : <About />} />
      </Routes>
    </Router>
  );
};

export default AppRoutes;
