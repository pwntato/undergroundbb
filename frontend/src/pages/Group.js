import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  Container,
  Typography,
  Box,
  Button,
  CircularProgress,
} from "@mui/material";
import { getGroupByUuid, getUserRoleInGroup } from "../api/groupAPI";
import { getPosts } from "../api/postAPI";
import PostItem from "../components/PostItem";

const Group = () => {
  const { uuid } = useParams();
  const [group, setGroup] = useState(null);
  const [error, setError] = useState("");
  const [userRole, setUserRole] = useState("");
  const [posts, setPosts] = useState([]);
  const [current, setCurrent] = useState(0);
  const [next, setNext] = useState(null);
  const [previous, setPrevious] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchGroup = async () => {
      try {
        const fetchedGroup = await getGroupByUuid(uuid);
        setGroup(fetchedGroup);
      } catch (error) {
        setError("Group not found");
      }
    };

    const fetchUserRole = async () => {
      try {
        const role = await getUserRoleInGroup(uuid);
        setUserRole(role["role"]);
      } catch (error) {
        console.error("Error fetching user role", error);
      }
    };

    fetchGroup();
    fetchUserRole();
  }, [uuid]);

  useEffect(() => {
    const fetchPosts = async () => {
      setLoading(true);
      try {
        const { posts: fetchedPosts, pagination: fetchedPagination } =
          await getPosts(uuid, current);
        setPosts(fetchedPosts);
        setNext(fetchedPagination.next);
        setPrevious(fetchedPagination.previous);
      } catch (error) {
        console.error("Error fetching posts", error);
      } finally {
        setLoading(false);
      }
    };

    fetchPosts();
  }, [uuid, current]);

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

  if (error) {
    return <div>{error}</div>;
  }

  if (!group) {
    return <div>Loading...</div>;
  }

  return (
    <Container maxWidth="md">
      <Box
        sx={{
          mt: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            width: "100%",
            justifyContent: "space-between",
          }}
        >
          <Typography component="h1" variant="h4" sx={{ mb: 2 }}>
            {group.name}
          </Typography>
          {(userRole === "admin" || userRole === "ambassador") && (
            <Box sx={{ display: "flex", alignItems: "center" }}>
              <Button
                variant="contained"
                color="primary"
                component={Link}
                to={`/group/${uuid}/invite`}
                sx={{ mr: 2 }}
              >
                Invite User
              </Button>
              {userRole === "admin" && (
                <Button
                  variant="contained"
                  color="primary"
                  component={Link}
                  to={`/group/${uuid}/edit`}
                  sx={{ ml: 2 }}
                >
                  Edit Group
                </Button>
              )}
              <Button
                variant="contained"
                color="primary"
                component={Link}
                to={`/group/${uuid}/create-post`}
                sx={{ ml: 2 }}
              >
                Create Post
              </Button>
            </Box>
          )}
        </Box>
        <Typography variant="body2" sx={{ mb: 4 }}>
          Created at: {new Date(group.created_at).toLocaleDateString()}
        </Typography>
        {group.description && (
          <Typography variant="body1" sx={{ mb: 4 }}>
            {group.description}
          </Typography>
        )}
        <Box sx={{ width: "100%", bgcolor: "background.paper", mb: 4 }}>
          {posts.map((post) => (
            <PostItem key={post.id} post={post} />
          ))}
        </Box>
        <Box sx={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
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
        {loading && <CircularProgress />}
      </Box>
    </Container>
  );
};

export default Group;
