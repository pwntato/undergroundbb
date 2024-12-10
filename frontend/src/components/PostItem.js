import React from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent, Box } from "@mui/material";
import DateComponent from "./DateComponent";

const PostItem = ({ post }) => {
  return (
    <Card sx={{ mb: 2, maxHeight: 100 }}>
      <CardContent sx={{ padding: "8px 16px" }}>
        <Typography
          variant="h6"
          component={Link}
          to={`/group/${post.group.uuid}/post/${post.uuid}`}
          gutterBottom
        >
          {post.title}
        </Typography>
        <Box
          sx={{
            display: "flex",
            justifyContent: "space-between",
            padding: "0 8px",
          }}
        >
          <Typography variant="body2" color="text.secondary">
            by{" "}
            <Link to={`/user/${post.author.uuid}`}>{post.author.username}</Link>{" "}
            created <DateComponent datetime={post.created_at} />
          </Typography>
          <Typography
            variant="body2"
            color="text.secondary"
            component={Link}
            to={`/group/${post.group.uuid}/post/${post.uuid}`}
          >
            {post.comments_count} comments
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

export default PostItem;
