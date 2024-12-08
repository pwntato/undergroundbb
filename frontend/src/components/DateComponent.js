import React from "react";
import { Tooltip, Typography } from "@mui/material";
import { format, formatDistanceToNow } from "date-fns";

const DateComponent = ({ datetime }) => {
  const date = new Date(datetime);
  const formattedDate = format(date, "PPpp");
  const timeAgo = formatDistanceToNow(date);

  return (
    <Tooltip title={formattedDate}>
      <Typography variant="body2">
        Created {timeAgo} ago
      </Typography>
    </Tooltip>
  );
};

export default DateComponent;
