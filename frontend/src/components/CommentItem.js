import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent, Box } from "@mui/material";
import DateComponent from "./DateComponent";
import CommentSection from "./CommentSection";

const CommentItem = ({ comment }) => {
  const [showReplies, setShowReplies] = useState(false);

  const handleToggleReplies = () => {
    setShowReplies((prev) => !prev);
  };

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="body1" sx={{ mb: 1 }}>
          {comment.body}
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
          <Box sx={{ pl: 4, mt: 2 }}>
            <CommentSection parentUuid={comment.uuid} groupUuid={comment.group.uuid} />
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default CommentItem;
