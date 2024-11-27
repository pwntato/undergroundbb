import React, { createContext, useReducer, useContext } from 'react';

const UserContext = createContext();

const initialState = {
  isLoggedIn: false,
  username: '',
  selectedGroup: { name: null, uuid: null },
  groups: [], // Initialize groups as an empty array
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
      return initialState;
    case 'SET_SELECTED_GROUP':
      return {
        ...state,
        selectedGroup: action.payload,
      };
    case 'SET_GROUPS':
      return {
        ...state,
        groups: action.payload,
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
