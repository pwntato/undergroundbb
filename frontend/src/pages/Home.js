import React, { useEffect, useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Container,
  Typography,
  Box,
  List,
  ListItem,
  ListItemText,
  Link,
} from "@mui/material";
import { getUserGroups } from "../api/groupAPI";

const Home = () => {
  const [groups, setGroups] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchUserGroups = async () => {
      try {
        const userGroups = await getUserGroups();
        setGroups(userGroups);
      } catch (error) {
        setError("Error fetching user groups");
      }
    };

    fetchUserGroups();
  }, []);

  if (error) {
    return <div>{error}</div>;
  }

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
          My Groups
        </Typography>
        <List sx={{ width: "100%" }}>
          {groups.map((group) => (
            <ListItem key={group.uuid}>
              <ListItemText
                primary={
                  <Link
                    component={RouterLink}
                    to={`/group/${group.uuid}`}
                    underline="hover"
                  >
                    {`${group.name} (${group.recentPosts})`}
                  </Link>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Container>
  );
};

export default Home;
