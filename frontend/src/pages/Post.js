import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Container, Typography, Box } from "@mui/material";
import { getPostByUuid } from "../api/postAPI";

const Post = () => {
  const { uuid } = useParams();
  const [post, setPost] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchPost = async () => {
      try {
        const fetchedPost = await getPostByUuid(uuid);
        setPost(fetchedPost);
      } catch (error) {
        setError("Post not found");
      }
    };

    fetchPost();
  }, [uuid]);

  if (error) {
    return <div>{error}</div>;
  }

  if (!post) {
    return <div>Loading...</div>;
  }

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 8, display: "flex", flexDirection: "column", alignItems: "center" }}>
        <Typography component="h1" variant="h4" sx={{ mb: 2 }}>
          {post.title}
        </Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          {post.body}
        </Typography>
        <Typography variant="body2" sx={{ mb: 2 }}>
          Created at: {new Date(post.created_at).toLocaleDateString()}
        </Typography>
        <Typography variant="body2">
          by <Link to={`/user/${post.author.uuid}`}>{post.author.username}</Link>
        </Typography>
      </Box>
    </Container>
  );
};

export default Post;