import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Container,
  TextField,
  Button,
  Typography,
  Box,
  Alert,
  FormControlLabel,
  Checkbox,
} from "@mui/material";
import { getGroupByUuid, editGroup } from "../api/groupAPI";

const EditGroup = () => {
  const { uuid } = useParams();
  const [group, setGroup] = useState(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [hidden, setHidden] = useState(false);
  const [trustTrace, setTrustTrace] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const fetchGroup = async () => {
      try {
        const fetchedGroup = await getGroupByUuid(uuid);
        setGroup(fetchedGroup);
        setName(fetchedGroup.name);
        setDescription(fetchedGroup.description);
        setHidden(fetchedGroup.hidden);
        setTrustTrace(fetchedGroup.trust_trace);
      } catch (error) {
        setError("Group not found");
      }
    };

    fetchGroup();
  }, [uuid]);

  const handleEditGroup = async (event) => {
    event.preventDefault();
    try {
      await editGroup(uuid, name, description, hidden, trustTrace);
      setSuccess("Group updated successfully");
      navigate(`/group/${uuid}`);
    } catch (error) {
      setError("Error updating group");
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
      </Box>
    </Container>
  );
};

export default EditGroup;
