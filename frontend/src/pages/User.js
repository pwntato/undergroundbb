import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Container, Typography, Box, Alert } from "@mui/material";
import { getUserByUuid } from "../api/userAPI";

const User = () => {
  const { uuid } = useParams();
  const [user, setUser] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const fetchedUser = await getUserByUuid(uuid);
        setUser(fetchedUser);
      } catch (error) {
        setError("User not found");
      }
    };

    fetchUser();
  }, [uuid]);

  if (error) {
    return (
      <Container maxWidth="sm">
        <Alert severity="error">{error}</Alert>
      </Container>
    );
  }

  if (!user) {
    return (
      <Container maxWidth="sm">
        <Typography>Loading...</Typography>
      </Container>
    );
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
          User Details
        </Typography>
        <Typography variant="body1" sx={{ mb: 1 }}>
          <strong>Username:</strong> {user.username}
        </Typography>
        <Typography variant="body1">
          <strong>Bio:</strong> {user.bio}
        </Typography>
      </Box>
    </Container>
  );
};

export default User;
