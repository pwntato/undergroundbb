import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  Container,
  TextField,
  Button,
  Typography,
  Box,
  Alert,
  FormControlLabel,
  Checkbox,
  Grid2,
  Select,
  MenuItem,
} from "@mui/material";
import { getGroupByUuid, editGroup, getUsersInGroup, updateUserRoleInGroup, getUserRoleInGroup } from "../api/groupAPI";

const EditGroup = () => {
  const { uuid } = useParams();
  const [group, setGroup] = useState(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [hidden, setHidden] = useState(false);
  const [trustTrace, setTrustTrace] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [users, setUsers] = useState([]);
  const [userRole, setUserRole] = useState("");

  useEffect(() => {
    const fetchGroup = async () => {
      try {
        const fetchedGroup = await getGroupByUuid(uuid);
        setGroup(fetchedGroup);
        setName(fetchedGroup.name);
        setDescription(fetchedGroup.description);
        setHidden(fetchedGroup.hidden ?? false);
        setTrustTrace(fetchedGroup.trust_trace ?? false);
      } catch (error) {
        setError("Group not found");
      }
    };

    const fetchUsers = async () => {
      try {
        const fetchedUsers = await getUsersInGroup(uuid);
        setUsers(fetchedUsers);
      } catch (error) {
        setError("Error fetching users");
      }
    };

    const fetchUserRole = async () => {
      try {
        const role = await getUserRoleInGroup(uuid);
        setUserRole(role.role);
      } catch (error) {
        setError("Error fetching user role");
      }
    };

    fetchGroup();
    fetchUsers();
    fetchUserRole();
  }, [uuid]);

  const handleEditGroup = async (event) => {
    event.preventDefault();
    try {
      await editGroup(uuid, name, description, hidden, trustTrace);
      setSuccess("Group updated successfully");
    } catch (error) {
      setError("Error updating group");
    }
  };

  const handleRoleChange = (userId, newRole) => {
    setUsers((prevUsers) =>
      prevUsers.map((user) =>
        user.id === userId ? { ...user, role: newRole } : user
      )
    );
  };

  const handleUpdateRole = async (userId, newRole) => {
    try {
      await updateUserRoleInGroup(uuid, userId, newRole);
      setSuccess("User role updated successfully");
    } catch (error) {
      setError("Error updating user role");
    }
  };

  if (error) {
    return <div>{error}</div>;
  }

  if (!group) {
    return <div>Loading...</div>;
  }

  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          mt: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Typography component="h1" variant="h5" sx={{ mb: 2 }}>
          Edit Group
        </Typography>
        {success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {success}
          </Alert>
        )}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        <Box component="form" onSubmit={handleEditGroup} sx={{ width: "100%" }}>
          <TextField
            variant="outlined"
            margin="normal"
            required
            fullWidth
            id="name"
            label="Group Name"
            name="name"
            autoComplete="name"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <TextField
            variant="outlined"
            margin="normal"
            fullWidth
            id="description"
            label="Description"
            name="description"
            multiline
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={hidden}
                onChange={(e) => setHidden(e.target.checked)}
                name="hidden"
                color="primary"
              />
            }
            label="Hidden"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={trustTrace}
                onChange={(e) => setTrustTrace(e.target.checked)}
                name="trustTrace"
                color="primary"
              />
            }
            label="Trust Trace"
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            color="primary"
            sx={{ mt: 3, mb: 2 }}
          >
            Save Changes
          </Button>
        </Box>
        {userRole === "admin" && (
          <Grid2 container spacing={2} sx={{ mt: 4 }}>
            {users.map((user) => (
              <Grid2 item={true} xs={12} sm={6} md={4} key={user.id}>
                <Typography>{user.username}</Typography>
                <Select
                  value={user.role}
                  onChange={(e) => handleRoleChange(user.id, e.target.value)}
                  fullWidth
                >
                  <MenuItem value="admin">Admin</MenuItem>
                  <MenuItem value="ambassador">Ambassador</MenuItem>
                  <MenuItem value="member">Member</MenuItem>
                  <MenuItem value="banned">Banned</MenuItem>
                </Select>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={() => handleUpdateRole(user.id, user.role)}
                  sx={{ mt: 1 }}
                >
                  Update
                </Button>
              </Grid2>
            ))}
          </Grid2>
        )}
      </Box>
    </Container>
  );
};

export default EditGroup;
