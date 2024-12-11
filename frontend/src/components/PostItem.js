import React from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent, Box } from "@mui/material";
import NotificationsIcon from "@mui/icons-material/Notifications";
import DateComponent from "./DateComponent";
import { useUser } from "../contexts/UserContext";

const PostItem = ({ post }) => {
  const { state } = useUser();

  const isNewComment = new Date(post.created_at) > new Date(state.lastLogin);

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
        {isNewComment && (
          <NotificationsIcon sx={{ color: "red", fontSize: 16, mr: 1 }} />
        )}
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
