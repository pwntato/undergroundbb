import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  Container,
  TextField,
  Button,
  Typography,
  Box,
  Alert,
  Grid,
} from "@mui/material";
import {
  getGroupByUuid,
  editGroup,
  getUsersInGroup,
  getUserRoleInGroup,
} from "../api/groupAPI";
import UserRoleUpdater from "../components/UserRoleUpdater";

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
        fetchedUsers.sort((a, b) => a.username.localeCompare(b.username));
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

  const handleUpdate = () => {
    // fetchUsers();
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
          <>
            <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>
              Users
            </Typography>
            <Grid container spacing={2}>
              {users.map((user) => (
                <UserRoleUpdater
                  key={user.uuid}
                  userUuid={user.uuid}
                  username={user.username}
                  userRole={user.role}
                  groupUuid={uuid}
                  onUpdate={handleUpdate}
                />
              ))}
            </Grid>
          </>
        )}
      </Box>
    </Container>
  );
};

export default EditGroup;
