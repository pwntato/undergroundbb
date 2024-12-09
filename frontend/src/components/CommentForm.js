import React, { useState } from "react";
import { Container, TextField, Button, Box, Alert } from "@mui/material";
import { createPost } from "../api/postAPI";

const CommentForm = ({ parentUuid, groupUuid }) => {
  const [body, setBody] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleCreateComment = async (event) => {
    event.preventDefault();
    setError("");
    setSuccess("");

    try {
      await createPost("", body, groupUuid, parentUuid);
      setSuccess("Comment added successfully");
      setBody("");
    } catch (error) {
      setError("Error adding comment");
    }
  };

  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          mt: 4,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}
        {success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {success}
          </Alert>
        )}
        <Box
          component="form"
          onSubmit={handleCreateComment}
          sx={{ width: "100%" }}
        >
          <TextField
            variant="outlined"
            margin="normal"
            required
            fullWidth
            name="body"
            label="Add a comment"
            type="text"
            id="body"
            multiline
            rows={4}
            value={body}
            onChange={(e) => setBody(e.target.value)}
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            color="primary"
            sx={{ mt: 3, mb: 2 }}
          >
            Add Comment
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default CommentForm;
