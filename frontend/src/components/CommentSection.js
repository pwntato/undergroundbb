import React, { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import { Container, Button, Box, CircularProgress, Typography } from "@mui/material";
import CommentForm from "./CommentForm";
import CommentItem from "./CommentItem";
import { getPosts } from "../api/postAPI";

const CommentSection = ({ parentUuid }) => {
  const { uuid: groupId } = useParams();
  const [comments, setComments] = useState([]);
  const [current, setCurrent] = useState(0);
  const [next, setNext] = useState(null);
  const [previous, setPrevious] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchComments = async () => {
      setLoading(true);
      try {
        const { posts: fetchedComments, pagination: fetchedPagination } = await getPosts(groupId, current, parentUuid);
        setComments(fetchedComments);
        setNext(fetchedPagination.next);
        setPrevious(fetchedPagination.previous);
      } catch (error) {
        setError("Error fetching comments");
      } finally {
        setLoading(false);
      }
    };

    fetchComments();
  }, [groupId, current, parentUuid]);

  const handleNextPage = () => {
    if (next !== null) {
      setCurrent(next);
    }
  };

  const handlePreviousPage = () => {
    if (previous !== null) {
      setCurrent(previous);
    }
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 4 }}>
        <CommentForm parentUuid={parentUuid} />
        {error && <Typography color="error">{error}</Typography>}
        {loading && <CircularProgress />}
        {comments.map((comment) => (
          <CommentItem key={comment.uuid} comment={comment} />
        ))}
        <Box sx={{ display: "flex", justifyContent: "space-between", width: "100%", mt: 2 }}>
          {previous >= 0 && (
            <Button variant="contained" color="primary" onClick={handlePreviousPage}>
              Previous
            </Button>
          )}
          <Box sx={{ flexGrow: 1 }} />
          <Button variant="contained" color="primary" onClick={handleNextPage} disabled={next === null}>
            Next
          </Button>
        </Box>
      </Box>
    </Container>
  );
};

export default CommentSection;

