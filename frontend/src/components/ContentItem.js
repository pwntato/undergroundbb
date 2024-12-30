import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Typography, Card, CardContent, Box, IconButton } from "@mui/material";
import NotificationsIcon from "@mui/icons-material/Notifications";
import DeleteIcon from "@mui/icons-material/Delete";
import DateComponent from "./DateComponent";
import CommentSection from "./CommentSection";
import { useUser } from "../contexts/UserContext";
import { deletePost } from "../api/postAPI";
import { getUserRoleInGroup } from "../api/groupAPI";
import { transformContent } from "../utils/contentTransform";

const urlRegex = /(https?:\/\/[^\s]+)/g;
const imageExtRegex = /\.(jpg|jpeg|png|gif|webp)$/i;

const ContentItem = ({ content, onDelete, userRole, isPost = false }) => {
  const [showReplies, setShowReplies] = useState(false);
  const [body, setBody] = useState(content.body);
  const [canDelete, setCanDelete] = useState(false);
  const { state } = useUser();
  const navigate = useNavigate();

  useEffect(() => {
    const checkDeletePermission = async () => {
      const isAuthor = state.uuid === content?.author?.uuid;
      if (isAuthor) {
        setCanDelete(true);
        return;
      }

      if (!isPost && content?.group?.uuid) {
        try {
          const response = await getUserRoleInGroup(content.group.uuid);
          setCanDelete(response?.role === "admin");
        } catch (error) {
          console.error("Error checking user role:", error);
          setCanDelete(false);
        }
      } else if (isPost) {
        setCanDelete(isAuthor || userRole === "admin");
      }
    };

    checkDeletePermission();
  }, [
    state.uuid,
    content?.author?.uuid,
    content?.group?.uuid,
    isPost,
    userRole,
  ]);

  const handleToggleReplies = () => {
    setShowReplies((prev) => !prev);
  };

  const handleDelete = async (e) => {
    if (e) e.preventDefault();

    if (window.confirm("Are you sure you want to delete this?")) {
      try {
        await deletePost(content.uuid);
        if (!isPost) {
          setBody("[DELETED]");
        }
        if (onDelete) {
          onDelete(content.uuid);
        } else if (isPost) {
          navigate(`/group/${content.group.uuid}`);
        }
      } catch (error) {
        console.error("Failed to delete:", error);
        alert("Failed to delete. Please try again.");
      }
    }
  };

  const isNewContent = new Date(content.created_at) > new Date(state.lastLogin);

  return (
    <Card sx={{ mb: 2, maxHeight: isPost ? 100 : "none" }}>
      <CardContent sx={{ padding: isPost ? "8px 16px" : "16px" }}>
        <Box
          sx={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          {isPost ? (
            <Typography
              variant="h6"
              component={Link}
              to={`/group/${content.group.uuid}/post/${content.uuid}`}
              gutterBottom
            >
              {content.title}
            </Typography>
          ) : (
            <Typography variant="body1" sx={{ mb: 1, flex: 1 }}>
              {transformContent(body)}
            </Typography>
          )}
          <Box sx={{ display: "flex", alignItems: "center" }}>
            {isNewContent && (
              <NotificationsIcon sx={{ color: "red", fontSize: 16, mr: 1 }} />
            )}
            {canDelete && (
              <IconButton
                size="small"
                onClick={handleDelete}
                sx={{ ml: 1 }}
                aria-label={`delete ${isPost ? "post" : "comment"}`}
              >
                <DeleteIcon />
              </IconButton>
            )}
          </Box>
        </Box>
        {isPost && content.body && (
          <Typography variant="body1" sx={{ mb: 1 }}>
            {transformContent(content.body)}
          </Typography>
        )}
        <Box
          sx={{
            display: "flex",
            justifyContent: "space-between",
            padding: isPost ? "0 8px" : "0",
          }}
        >
          <Typography variant="body2" color="text.secondary">
            {isPost ? "by " : "Created "}
            <Link to={`/user/${content.author.uuid}`}>
              {content.author.username}
            </Link>{" "}
            {isPost ? "created " : null}
            <DateComponent datetime={content.created_at} />
          </Typography>
          <Typography
            variant="body2"
            color="text.secondary"
            component={isPost ? Link : "span"}
            to={
              isPost
                ? `/group/${content.group.uuid}/post/${content.uuid}`
                : undefined
            }
            onClick={!isPost ? handleToggleReplies : undefined}
            sx={!isPost ? { cursor: "pointer" } : {}}
          >
            {content.comments_count} comments
          </Typography>
        </Box>
        {!isPost && showReplies && (
          <Box sx={{ mt: 2 }}>
            <CommentSection
              parentUuid={content.uuid}
              groupUuid={content?.group?.uuid}
            />
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default ContentItem;
