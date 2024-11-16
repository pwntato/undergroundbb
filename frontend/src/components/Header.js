import React from 'react';

const Header = ({ isLoggedIn, username, onLogout, onShowLogin, onShowSignup }) => {
  return (
    <div style={{ position: 'absolute', top: 0, left: 0, padding: '10px' }}>
      {isLoggedIn ? (
        <>
          <span>{username}</span>
          <button onClick={onLogout} style={{ marginLeft: '10px' }}>Logout</button>
        </>
      ) : (
        <>
          <button onClick={onShowSignup} style={{ marginRight: '10px' }}>Sign Up</button>
          <button onClick={onShowLogin}>Login</button>
        </>
      )}
    </div>
  );
};

export default Header;
