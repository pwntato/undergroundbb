import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Container, Typography, Box } from "@mui/material";
import { getPostByUuid } from "../api/postAPI";
import DateComponent from "../components/DateComponent";
import CommentSection from "../components/CommentSection";

const Post = () => {
  const { postUuid, groupUuid } = useParams();
  const [post, setPost] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchPost = async () => {
      try {
        const fetchedPost = await getPostByUuid(postUuid);
        setPost(fetchedPost);
      } catch (error) {
        setError("Post not found");
      }
    };

    fetchPost();
  }, [postUuid]);

  if (error) {
    return <div>{error}</div>;
  }

  if (!post) {
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
        <Box sx={{ alignSelf: "flex-start", mb: 2 }}>
          <Link to={`/group/${groupUuid}`}>Back to Group</Link>
        </Box>
        <Typography component="h1" variant="h4" sx={{ mb: 2 }}>
          {post.title}
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          {post.body}
        </Typography>
        <Typography variant="body2" component="span">
          Created <DateComponent datetime={post.created_at} /> by{" "}
          <Link to={`/user/${post.author.uuid}`}>{post.author.username}</Link>
        </Typography>
        <CommentSection parentUuid={post.uuid} groupUuid={groupUuid} />
      </Box>
    </Container>
  );
};

export default Post;
