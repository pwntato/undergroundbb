import React, { useState } from "react";
import { Container, TextField, Button, Box, Alert, Link } from "@mui/material";
import { createPost } from "../api/postAPI";

const CommentForm = ({ parentUuid, groupUuid, onCommentAdded }) => {
  const [body, setBody] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [showForm, setShowForm] = useState(false);

  const handleCreateComment = async (event) => {
    event.preventDefault();
    setError("");
    setSuccess("");

    try {
      const newComment = await createPost("", body, groupUuid, parentUuid);
      setSuccess("Comment added successfully");
      setBody("");
      onCommentAdded(newComment);
    } catch (error) {
      setError("Error adding comment");
    }
  };

  const toggleFormVisibility = () => {
    setShowForm((prev) => !prev);
  };

  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          mt: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Link component="button" variant="body2" onClick={toggleFormVisibility}>
          {showForm ? "Hide Comment Form" : "Add a Comment"}
        </Link>
        {showForm && (
          <>
            {error && (
              <Alert severity="error" sx={{ mb: 1 }}>
                {error}
              </Alert>
            )}
            {success && (
              <Alert severity="success" sx={{ mb: 1 }}>
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
                sx={{ mt: 1, mb: 1 }}
              >
                Add Comment
              </Button>
            </Box>
          </>
        )}
      </Box>
    </Container>
  );
};

export default CommentForm;
