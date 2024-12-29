import React, { createContext, useReducer, useContext } from "react";

const UserContext = createContext();

const initialState = {
  isLoggedIn: false,
  username: "",
  uuid: null,
  selectedGroup: { name: null, uuid: null },
  lastLogin: null,
  groups: [],
};

const userReducer = (state, action) => {
  console.log("action", action);
  switch (action.type) {
    case "LOGIN":
      return {
        ...state,
        isLoggedIn: true,
        username: action.payload.username,
        uuid: action.payload.uuid,
        lastLogin: action.payload.lastLogin,
      };
    case "LOGOUT":
      return initialState;
    case "SET_SELECTED_GROUP":
      return {
        ...state,
        selectedGroup: action.payload,
      };
    case "SET_GROUPS":
      return {
        ...state,
        groups: action.payload,
      };
    case "ADD_GROUP":
      return {
        ...state,
        groups: {
          ...state.groups,
          [action.payload.uuid]: action.payload,
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
