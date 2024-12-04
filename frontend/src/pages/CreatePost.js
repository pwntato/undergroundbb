import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Container, TextField, Button, Typography, Box, Alert } from "@mui/material";
import { createPost } from "../api/postAPI";

const CreatePost = () => {
  const { groupId } = useParams();
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const navigate = useNavigate();

  const handleCreatePost = async (event) => {
    event.preventDefault();
    setError("");
    setSuccess("");

    try {
      await createPost(title, body, groupId);
      setSuccess("Post created successfully");
      navigate(`/group/${groupId}`);
    } catch (error) {
      setError("Error creating post");
    }
  };

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8, display: "flex", flexDirection: "column", alignItems: "center" }}>
        <Typography component="h1" variant="h5" sx={{ mb: 2 }}>
          Create Post
        </Typography>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {success && <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>}
        <Box component="form" onSubmit={handleCreatePost} sx={{ width: "100%" }}>
          <TextField
            variant="outlined"
            margin="normal"
            required
            fullWidth
            id="title"
            label="Post Title"
            name="title"
            autoComplete="title"
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
          <TextField
            variant="outlined"
            margin="normal"
            required
            fullWidth
            name="body"
            label="Post Body"
            type="text"
            id="body"
            multiline
            rows={4}
            value={body}
            onChange={(e) => setBody(e.target.value)}
          />
          <Button type="submit" fullWidth variant="contained" color="primary" sx={{ mt: 3, mb: 2 }}>
            Create Post
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default CreatePost;
