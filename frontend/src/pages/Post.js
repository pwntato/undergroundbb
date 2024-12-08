import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Container, Typography, Box, Tooltip } from "@mui/material";
import { formatDistanceToNow, format } from "date-fns";
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

  const createdAt = new Date(post.created_at);
  const formattedDate = format(createdAt, "PPpp");

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 8, display: "flex", flexDirection: "column", alignItems: "center" }}>
        <Typography component="h1" variant="h4" sx={{ mb: 2 }}>
          {post.title}
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          {post.body}
        </Typography>
        <Tooltip title={formattedDate}>
          <Typography variant="body2">
            Created {formatDistanceToNow(createdAt)} ago by <Link to={`/user/${post.author.uuid}`}>{post.author.username}</Link>
          </Typography>
        </Tooltip>
      </Box>
    </Container>
  );
};

export default Post;