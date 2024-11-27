import React, { createContext, useReducer, useContext } from 'react';

const UserContext = createContext();

const initialState = {
  isLoggedIn: false,
  username: '',
  selectedGroup: {
    name: null,
    uuid: null,
  },
};

const userReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN':
      return {
        ...state,
        isLoggedIn: true,
        username: action.payload.username,
        selectedGroup: {
          name: null,
          uuid: null,
        },
      };
    case 'LOGOUT':
      return {
        ...state,
        isLoggedIn: false,
        username: '',
        selectedGroup: {
          name: null,
          uuid: null,
        },
      };
    case 'SET_SELECTED_GROUP':
      return {
        ...state,
        selectedGroup: {
          name: action.payload.name,
          uuid: action.payload.uuid,
        },
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
