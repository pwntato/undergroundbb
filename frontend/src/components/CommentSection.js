import React, { useState, useEffect } from "react";
import {
  Container,
  Button,
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
        <CommentForm
          parentUuid={parentUuid}
          groupUuid={groupUuid}
          onCommentAdded={handleCommentAdded}
        />
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
          <Button
            variant="contained"
            color="primary"
            onClick={handleMore}
            disabled={next === null}
          >
            More
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default CommentSection;
