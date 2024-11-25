import React, { createContext, useReducer, useContext } from 'react';

const UserContext = createContext();

const initialState = {
  isLoggedIn: false,
  username: '',
};

const userReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN':
      return {
        ...state,
        isLoggedIn: true,
        username: action.payload.username,
      };
    case 'LOGOUT':
      return {
        ...state,
        isLoggedIn: false,
        username: '',
      };
    default:
      return state;
  }
};

export const UserProvider = ({ children }) => {
  const [state, dispatch] = useReducer(userReducer, initialState);

  return (
    <UserContext.Provider value={{ state, dispatch }}>
      {children}
    </UserContext.Provider>
  );
};

export const useUser = () => useContext(UserContext);
