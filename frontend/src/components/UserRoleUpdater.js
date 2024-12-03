import React, { useState } from "react";
import { Typography, Select, MenuItem, Button, Box, Grid } from "@mui/material";
import { updateUserRoleInGroup } from "../api/groupAPI";

const UserRoleUpdater = ({
  userUuid,
  username,
  userRole,
  groupUuid,
  onUpdate,
}) => {
  const [role, setRole] = useState(userRole);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleRoleChange = (event) => {
    setRole(event.target.value);
  };

  const handleUpdateRole = async () => {
    try {
      await updateUserRoleInGroup(groupUuid, userUuid, role);
      setSuccess("User role updated successfully");
      setError("");
      if (onUpdate) {
        onUpdate();
      }
    } catch (error) {
      setError("Error updating user role");
      setSuccess("");
    }
  };

  return (
    <Box sx={{ mt: 0.5, mb: 0.5 }}>
      <Grid container alignItems="center" spacing={0.5} sx={{ mb: 0.5 }}>
        <Grid item xs={4}>
          <Typography
            variant="body2"
            sx={{ fontWeight: "bold", textAlign: "right" }}
          >
            {username}
          </Typography>
        </Grid>
        <Grid item xs={4}>
          <Select
            value={role}
            onChange={handleRoleChange}
            fullWidth
            size="small"
            sx={{ minWidth: 140 }}
          >
            <MenuItem value="admin">Admin</MenuItem>
            <MenuItem value="ambassador">Ambassador</MenuItem>
            <MenuItem value="member">Member</MenuItem>
            <MenuItem value="banned">Banned</MenuItem>
          </Select>
        </Grid>
        <Grid item xs={4}>
          <Button
            variant="contained"
            color="primary"
            onClick={handleUpdateRole}
            size="small"
            fullWidth
          >
            Update
          </Button>
        </Grid>
      </Grid>
      {error && (
        <Typography color="error" variant="body2">
          {error}
        </Typography>
      )}
      {success && (
        <Typography color="success" variant="body2">
          {success}
        </Typography>
      )}
    </Box>
  );
};

export default UserRoleUpdater;
