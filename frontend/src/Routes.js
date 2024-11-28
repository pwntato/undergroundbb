import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Header from './components/Header';
import Login from './pages/Login';
import CreateUser from './pages/CreateUser';
import User from './pages/User';
import Home from './pages/Home';
import About from './pages/About';
import Profile from './pages/Profile';
import CreateGroup from './pages/CreateGroup';
import { useUser } from './contexts/UserContext';
import PrivateRoute from './components/PrivateRoute';

const AppRoutes = () => {
  const { state } = useUser();

  return (
    <Router future={{ v7_relativeSplatPath: true, v7_startTransition: true }}>
      <Header />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<CreateUser />} />
        <Route path="/profile" element={<PrivateRoute><Profile /></PrivateRoute>} />
        <Route path="/user/:uuid" element={<PrivateRoute><User /></PrivateRoute>} />
        <Route path="/about" element={<About />} />
        <Route path="/create-group" element={<PrivateRoute><CreateGroup /></PrivateRoute>} />
        <Route path="/" element={state.isLoggedIn ? <Home /> : <About />} />
      </Routes>
    </Router>
  );
};

export default AppRoutes;
