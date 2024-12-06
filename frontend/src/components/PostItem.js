import React from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent } from "@mui/material";

const PostItem = ({ post }) => {
  return (
    <Card sx={{ mb: 2, maxHeight: 100 }}>
      <CardContent sx={{ padding: "2px" }}>
        <Typography
          variant="h6"
          component={Link}
          to={`/post/${post.id}`}
          gutterBottom
        >
          {post.title}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          by{" "}
          <Link to={`/user/${post.author.uuid}`}>{post.author.username}</Link>{" "}
          {new Date(post.created_at).toLocaleString()}
        </Typography>
      </CardContent>
    </Card>
  );
};

export default PostItem;
