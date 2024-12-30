import React, { useState } from "react";
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Menu,
  MenuItem,
  Divider,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import { useUser } from "../contexts/UserContext";
import { logoutUser } from "../api/userAPI";

const Header = () => {
  const { state, dispatch } = useUser();
  const [anchorEl, setAnchorEl] = useState(null);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logoutUser();
    dispatch({ type: "LOGOUT" });
  };

  const handleMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleGroupSelect = (group) => {
    dispatch({
      type: "SET_SELECTED_GROUP",
      payload: { name: group.name, uuid: group.uuid },
    });
    handleMenuClose();
    navigate(`/group/${group.uuid}`);
  };

  const handleCreateGroup = () => {
    navigate("/create-group");
    handleMenuClose();
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          <Button
            color="inherit"
            component={Link}
            to="/"
            sx={{ textTransform: "none", fontSize: "1.5rem" }}
          >
            <span>
              UndergroundBB{" "}
              <span
                style={{
                  color: "red",
                  fontSize: "x-small",
                  fontWeight: "bold",
                }}
              >
                BETA
              </span>
            </span>
          </Button>
        </Typography>
        <Button
          color="inherit"
          component={Link}
          to="https://github.com/pwntato/undergroundbb"
          target="_blank"
          sx={{
            backgroundColor: "#1565c0",
            "&:hover": {
              backgroundColor: "#0d47a1",
            },
            marginRight: 2,
          }}
        >
          Code
        </Button>
        <Button
          color="inherit"
          component={Link}
          to="https://www.patreon.com/c/UndergroundBB"
          target="_blank"
          sx={{
            backgroundColor: "#4caf50",
            "&:hover": {
              backgroundColor: "#388e3c",
            },
            marginRight: 2,
          }}
        >
          Donate
        </Button>
        <Button color="inherit" component={Link} to="/about">
          About
        </Button>
        {state.isLoggedIn && (
          <>
            <Button color="inherit" onClick={handleMenuOpen}>
              {state.selectedGroup.name || "Groups"}
            </Button>
            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
            >
              {state.groups &&
                Object.entries(state.groups)
                  .sort(([uuidA, nameA], [uuidB, nameB]) => {
                    if (uuidA === state.selectedGroup.uuid) return -1;
                    if (uuidB === state.selectedGroup.uuid) return 1;
                    return nameA.localeCompare(nameB);
                  })
                  .map(([uuid, name]) => (
                    <MenuItem
                      key={uuid}
                      onClick={() => handleGroupSelect({ uuid, name })}
                    >
                      {name}
                    </MenuItem>
                  ))}
              <Divider />
              <MenuItem onClick={handleCreateGroup}>Create Group</MenuItem>
            </Menu>
            <Button color="inherit" component={Link} to="/profile">
              {state.username}
            </Button>
            <Button color="inherit" onClick={handleLogout}>
              Logout
            </Button>
          </>
        )}
        {!state.isLoggedIn && (
          <>
            <Button color="inherit" component={Link} to="/login">
              Login
            </Button>
            <Button color="inherit" component={Link} to="/signup">
              Signup
            </Button>
          </>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Header;
