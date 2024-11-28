import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Container, Typography, Box } from "@mui/material";
import { getGroupByUuid } from "../api/groupAPI";

const Group = () => {
  const { uuid } = useParams();
  const [group, setGroup] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchGroup = async () => {
      try {
        const fetchedGroup = await getGroupByUuid(uuid);
        setGroup(fetchedGroup);
      } catch (error) {
        setError("Group not found");
      }
    };

    fetchGroup();
  }, [uuid]);

  if (error) {
    return <div>{error}</div>;
  }

  if (!group) {
    return <div>Loading...</div>;
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
        <Typography component="h1" variant="h4" sx={{ mb: 2 }}>
          {group.name}
        </Typography>
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
