import React, { useState, useEffect } from "react";
import {
  Container,
  Link,
  Box,
  CircularProgress,
  Typography,
} from "@mui/material";
import CommentForm from "./CommentForm";
import CommentItem from "./CommentItem";
import { getPosts } from "../api/postAPI";

const CommentSection = ({ parentUuid, groupUuid }) => {
  const [comments, setComments] = useState([]);
  const [current, setCurrent] = useState(0);
  const [next, setNext] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(false);

  useEffect(() => {
    const fetchComments = async () => {
      setLoading(true);
      try {
        const { posts: fetchedComments, pagination: fetchedPagination } =
          await getPosts(groupUuid, current, parentUuid);
        setComments((prevComments) => {
          const newComments = fetchedComments.filter(
            (comment) => !prevComments.some((prevComment) => prevComment.uuid === comment.uuid)
          );
          return [...prevComments, ...newComments];
        });
        setNext(fetchedPagination.next);
      } catch (error) {
        setError("Error fetching comments");
      } finally {
        setLoading(false);
      }
    };

    fetchComments();
  }, [groupUuid, current, parentUuid, refresh]);

  const handleMore = () => {
    if (next !== null) {
      setCurrent(next);
    }
  };

  const handleCommentAdded = () => {
    setRefresh((prev) => !prev);
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 4 }}>
        {error && <Typography color="error">{error}</Typography>}
        {loading && <CircularProgress />}
        {comments.map((comment) => (
          <CommentItem key={comment.uuid} comment={comment} />
        ))}
        <Box
          sx={{
            display: "flex",
            justifyContent: "center",
            width: "100%",
            mt: 2,
          }}
        >
          <Link
            component="button"
            variant="body2"
            onClick={handleMore}
            disabled={next === null}
            sx={{ textDecoration: "underline", color: "primary.main", cursor: "pointer", background: "none", border: "none", padding: 0 }}
          >
            More
          </Link>
        </Box>
        <CommentForm
          parentUuid={parentUuid}
          groupUuid={groupUuid}
          onCommentAdded={handleCommentAdded}
        />
      </Box>
    </Container>
  );
};

export default CommentSection;
