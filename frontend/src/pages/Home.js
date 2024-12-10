import React, { useEffect, useState } from "react";
import {
  Container,
  Typography,
  Box,
  List,
  ListItem,
  ListItemText,
  Button,
} from "@mui/material";
import { Link } from "react-router-dom";
import { useUser } from "../contexts/UserContext";
import { getPostCountSinceLastLogin } from "../api/groupAPI";

const Home = () => {
  const { state } = useUser();
  const [groups, setGroups] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchGroups = async () => {
      try {
        const userGroups = state.groups;
        const groupsWithPostCounts = await Promise.all(
          userGroups.map(async (group) => {
            const postCount = await getPostCountSinceLastLogin(group.uuid);
            return { ...group, postCount };
          })
        );
        setGroups(groupsWithPostCounts);
      } catch (error) {
        setError("Error fetching groups");
      }
    };

    fetchGroups();
  }, [state.groups]);

  return (
    <Container maxWidth="md">
      <Box
        sx={{
          mt: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Typography component="h1" variant="h4" sx={{ mb: 4 }}>
          Welcome to TrustBoard
        </Typography>
        <Typography component="h2" variant="h5" sx={{ mb: 2 }}>
          Your Groups
        </Typography>
        {error && <Typography color="error">{error}</Typography>}
        <List sx={{ width: "100%", bgcolor: "background.paper", mb: 4 }}>
          {groups.map((group) => (
            <ListItem
              key={group.uuid}
              sx={{ display: "flex", justifyContent: "space-between" }}
            >
              <ListItemText
                primary={<Link to={`/group/${group.uuid}`}>{group.name}</Link>}
              />
              <Typography variant="body2" color="text.secondary">
                {group.postCount} recent posts
              </Typography>
            </ListItem>
          ))}
        </List>
        <Button
          variant="contained"
          color="primary"
          component={Link}
          to="/search"
        >
          Search for Users or Groups
        </Button>
      </Box>
    </Container>
  );
};

export default Home;
