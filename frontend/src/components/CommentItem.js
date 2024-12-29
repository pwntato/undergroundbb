import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent, Box, IconButton } from "@mui/material";
import NotificationsIcon from "@mui/icons-material/Notifications";
import DeleteIcon from "@mui/icons-material/Delete";
import DateComponent from "./DateComponent";
import CommentSection from "./CommentSection";
import { useUser } from "../contexts/UserContext";
import { deletePost } from "../api/postAPI";
import { getUserRoleInGroup } from "../api/groupAPI";

const CommentItem = ({ comment, onCommentDeleted }) => {
  const [showReplies, setShowReplies] = useState(false);
  const [body, setBody] = useState(comment.body);
  const [canDelete, setCanDelete] = useState(false);
  const { state } = useUser();

  useEffect(() => {
    const checkDeletePermission = async () => {
      const isAuthor = state.uuid === comment?.author?.uuid;
      if (isAuthor) {
        setCanDelete(true);
        return;
      }
      
      if (comment?.group?.uuid) {
        try {
          const response = await getUserRoleInGroup(comment.group.uuid);
          setCanDelete(response?.role === "admin");
        } catch (error) {
          console.error("Error checking user role:", error);
          setCanDelete(false);
        }
      }
    };
    
    checkDeletePermission();
  }, [state.uuid, comment?.author?.uuid, comment?.group?.uuid]);

  const handleToggleReplies = () => {
    setShowReplies((prev) => !prev);
  };

  const handleDelete = async () => {
    try {
      await deletePost(comment.uuid);
      setBody("[DELETED]");
      if (onCommentDeleted) {
        onCommentDeleted(comment.uuid);
      }
    } catch (error) {
      console.error(error);
    }
  };

  const isNewComment = new Date(comment.created_at) > new Date(state.lastLogin);

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <Typography variant="body1" sx={{ mb: 1, flex: 1 }}>
            {body}
            {isNewComment && (
              <NotificationsIcon sx={{ color: "red", fontSize: 16, mr: 1 }} />
            )}
          </Typography>
          {canDelete && (
            <IconButton onClick={handleDelete} size="small" sx={{ ml: 1 }}>
              <DeleteIcon />
            </IconButton>
          )}
        </Box>
        <Box sx={{ display: "flex", justifyContent: "space-between" }}>
          <Typography variant="body2" color="text.secondary">
            Created <DateComponent datetime={comment.created_at} /> by{" "}
            <Link to={`/user/${comment?.author?.uuid}`}>
              {comment?.author?.username}
            </Link>
          </Typography>
          <Typography
            variant="body2"
            color="text.secondary"
            component="span"
            onClick={handleToggleReplies}
            sx={{ cursor: "pointer" }}
          >
            {comment.comments_count} comments
          </Typography>
        </Box>
        {showReplies && (
          <Box sx={{ mt: 2 }}>
            <CommentSection
              parentUuid={comment.uuid}
              groupUuid={comment?.group?.uuid}
            />
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default CommentItem;
