import React, { useState, useEffect } from "react";
import {
  Container,
  Typography,
  TextField,
  Box,
  Button,
  Alert,
} from "@mui/material";
import { getCurrentUser, updateUser, changePassword } from "../api/userAPI";

const Profile = () => {
  const [user, setUser] = useState(null);
  const [email, setEmail] = useState("");
  const [bio, setBio] = useState("");
  const [hidden, setHidden] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [reenterPassword, setReenterPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [updateMessage, setUpdateMessage] = useState("");
  const [passwordMessage, setPasswordMessage] = useState("");

  useEffect(() => {
    const fetchUser = async () => {
      const currentUser = await getCurrentUser();
      setUser(currentUser);
      setEmail(currentUser.email || "");
      setBio(currentUser.bio || "");
      setHidden(currentUser.hidden || false);
    };
    fetchUser();
  }, []);

  const handleUpdate = async () => {
    try {
      await updateUser({ email, bio, hidden });
      setUpdateMessage("Profile updated successfully");
    } catch (error) {
      setUpdateMessage("Error updating profile");
    }
  };

  const handleChangePassword = async () => {
    if (newPassword !== reenterPassword) {
      setPasswordError("Passwords do not match");
      return;
    }
    try {
      const result = await changePassword(currentPassword, newPassword);
      if (result.error) {
        setPasswordMessage(result.error);
        return;
      } else {
        setPasswordMessage("Password changed successfully");
      }
    } catch (error) {
      setPasswordMessage("Error changing password");
    }
  };

  if (!user) {
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
        <Typography component="h1" variant="h4" sx={{ mb: 2 }}>
          {user.username}
        </Typography>
        <Typography variant="body2" sx={{ mb: 4 }}>
          User since: {new Date(user.created_at).toLocaleDateString()}
        </Typography>
        {updateMessage && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {updateMessage}
          </Alert>
        )}
        <TextField
          variant="outlined"
          margin="normal"
          fullWidth
          label="Public bio"
          multiline
          rows={4}
          value={bio}
          onChange={(e) => setBio(e.target.value)}
        />
        <Button
          variant="contained"
          color="primary"
          onClick={handleUpdate}
          sx={{ mt: 2, mb: 4 }}
        >
          Update
        </Button>
        {passwordMessage && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {passwordMessage}
          </Alert>
        )}
        <TextField
          variant="outlined"
          margin="normal"
          fullWidth
          label="Current Password"
          type="password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
        />
        <TextField
          variant="outlined"
          margin="normal"
          fullWidth
          label="New Password"
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          onBlur={() => {
            if (newPassword !== reenterPassword) {
              setPasswordError("Passwords do not match");
            } else {
              setPasswordError("");
            }
          }}
        />
        <TextField
          variant="outlined"
          margin="normal"
          fullWidth
          label="Re-enter New Password"
          type="password"
          value={reenterPassword}
          onChange={(e) => setReenterPassword(e.target.value)}
          onBlur={() => {
            if (newPassword !== reenterPassword) {
              setPasswordError("Passwords do not match");
            } else {
              setPasswordError("");
            }
          }}
          error={!!passwordError}
          helperText={passwordError}
        />
        <Button
          variant="contained"
          color="secondary"
          onClick={handleChangePassword}
          sx={{ mt: 2 }}
        >
          Change Password
        </Button>
      </Box>
    </Container>
  );
};

export default Profile;
