import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { Typography, Card, CardContent, Box, IconButton } from "@mui/material";
import NotificationsIcon from "@mui/icons-material/Notifications";
import DeleteIcon from "@mui/icons-material/Delete";
import DateComponent from "./DateComponent";
import { useUser } from "../contexts/UserContext";
import { deletePost } from "../api/postAPI";

const PostItem = ({ post, onDelete }) => {
  const { state } = useUser();
  const navigate = useNavigate();

  const isNewComment = new Date(post.created_at) > new Date(state.lastLogin);
  const isAuthor = state.uuid === post.author.uuid;
  console.log("state", state);

  const handleDelete = async (e) => {
    e.preventDefault(); // Prevent navigation
    if (window.confirm("Are you sure you want to delete this post?")) {
      try {
        await deletePost(post.uuid);
        if (onDelete) {
          onDelete(post.uuid);
        } else {
          navigate(`/group/${post.group.uuid}`);
        }
      } catch (error) {
        console.error("Failed to delete post:", error);
        alert("Failed to delete post. Please try again.");
      }
    }
  };

  return (
    <Card sx={{ mb: 2, maxHeight: 100 }}>
      <CardContent sx={{ padding: "8px 16px" }}>
        <Box
          sx={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Typography
            variant="h6"
            component={Link}
            to={`/group/${post.group.uuid}/post/${post.uuid}`}
            gutterBottom
          >
            {post.title}
          </Typography>
          {isAuthor && (
            <IconButton
              size="small"
              onClick={handleDelete}
              sx={{ ml: 1 }}
              aria-label="delete post"
            >
              <DeleteIcon />
            </IconButton>
          )}
        </Box>
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
