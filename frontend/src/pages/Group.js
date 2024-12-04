import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Container, Typography, Box, Button } from "@mui/material";
import { getGroupByUuid, getUserRoleInGroup } from "../api/groupAPI";

const Group = () => {
  const { uuid } = useParams();
  const [group, setGroup] = useState(null);
  const [error, setError] = useState("");
  const [userRole, setUserRole] = useState("");

  useEffect(() => {
    const fetchGroup = async () => {
      try {
        const fetchedGroup = await getGroupByUuid(uuid);
        setGroup(fetchedGroup);
      } catch (error) {
        setError("Group not found");
      }
    };

    const fetchUserRole = async () => {
      try {
        const role = await getUserRoleInGroup(uuid);
        setUserRole(role["role"]);
      } catch (error) {
        console.error("Error fetching user role", error);
      }
    };

    fetchGroup();
    fetchUserRole();
  }, [uuid]);

  if (error) {
    return <div>{error}</div>;
  }

  if (!group) {
    return <div>Loading...</div>;
  }

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 8, display: "flex", flexDirection: "column", alignItems: "center" }}>
        <Box sx={{ display: "flex", alignItems: "center", width: "100%", justifyContent: "space-between" }}>
          <Typography component="h1" variant="h4" sx={{ mb: 2 }}>
            {group.name}
          </Typography>
          {(userRole === "admin" || userRole === "ambassador") && (
            <Box sx={{ display: "flex", alignItems: "center" }}>
              <Button variant="contained" color="primary" component={Link} to={`/group/${uuid}/invite`} sx={{ mr: 2 }}>
                Invite User
              </Button>
              {userRole === "admin" && (
                <Button variant="contained" color="primary" component={Link} to={`/group/${uuid}/edit`} sx={{ ml: 2 }}>
                  Edit Group
                </Button>
              )}
              <Button variant="contained" color="primary" component={Link} to={`/group/${uuid}/create-post`} sx={{ ml: 2 }}>
                Create Post
              </Button>
            </Box>
          )}
        </Box>
        <Typography variant="body2" sx={{ mb: 4 }}>
          Created at: {new Date(group.created_at).toLocaleDateString()}
        </Typography>
        {group.description && (
          <Typography variant="body1" sx={{ mb: 4 }}>
            {group.description}
          </Typography>
        )}
      </Box>
    </Container>
  );
};

export default Group;
