import React from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent } from "@mui/material";
import DateComponent from "./DateComponent";

const PostItem = ({ post }) => {
  return (
    <Card sx={{ mb: 2, maxHeight: 100 }}>
      <CardContent sx={{ padding: "2px" }}>
        <Typography
          variant="h6"
          component={Link}
          to={`/post/${post.uuid}`}
          gutterBottom
        >
          {post.title}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          by{" "}
          <Link to={`/user/${post.author.uuid}`}>{post.author.username}</Link>{" "}
          <DateComponent datetime={post.created_at} />
        </Typography>
      </CardContent>
    </Card>
  );
};

export default PostItem;
