import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent, Box } from "@mui/material";
import NotificationsIcon from "@mui/icons-material/Notifications";
import DateComponent from "./DateComponent";
import CommentSection from "./CommentSection";
import { useUser } from "../contexts/UserContext";

const CommentItem = ({ comment }) => {
  const [showReplies, setShowReplies] = useState(false);
  const { state } = useUser();

  const handleToggleReplies = () => {
    setShowReplies((prev) => !prev);
  };

  const isNewComment = new Date(comment.created_at) > new Date(state.lastLogin);

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="body1" sx={{ mb: 1 }}>
          {comment.body}
          {isNewComment && (
            <NotificationsIcon sx={{ color: "red", fontSize: 16, mr: 1 }} />
          )}
        </Typography>
        <Box sx={{ display: "flex", justifyContent: "space-between" }}>
          <Typography variant="body2" color="text.secondary">
            Created <DateComponent datetime={comment.created_at} /> by{" "}
            <Link to={`/user/${comment.author.uuid}`}>
              {comment.author.username}
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
              groupUuid={comment.group.uuid}
            />
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default CommentItem;
