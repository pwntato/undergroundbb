import React from "react";
import { Link } from "react-router-dom";
import { Typography, Card, CardContent } from "@mui/material";
import DateComponent from "./DateComponent";

const CommentItem = ({ comment }) => {
  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="body1" sx={{ mb: 1 }}>
          {comment.body}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Created <DateComponent datetime={comment.created_at} /> by{" "}
          <Link to={`/user/${comment.author.uuid}`}>
            {comment.author.username}
          </Link>
        </Typography>
      </CardContent>
    </Card>
  );
};

export default CommentItem;
