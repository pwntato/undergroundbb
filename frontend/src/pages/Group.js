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
import DateComponent from "../components/DateComponent";

const Group = () => {
  const { uuid } = useParams();
  const [group, setGroup] = useState(null);
  const [error, setError] = useState("");
  const [userRole, setUserRole] = useState("");
  const [posts, setPosts] = useState([]);
  const [current, setCurrent] = useState(0);
  const [next, setNext] = useState(null);
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
        setPosts((prevPosts) => {
          const newPosts = fetchedPosts.filter(
            (post) => !prevPosts.some((prevPost) => prevPost.uuid === post.uuid)
          );
          return [...prevPosts, ...newPosts];
        });
        setNext(fetchedPagination.next);
      } catch (error) {
        console.error("Error fetching posts", error);
      } finally {
        setLoading(false);
      }
    };

    fetchPosts();
  }, [uuid, current]);

  const handleMore = () => {
    if (next !== null) {
      setCurrent(next);
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
          <Box sx={{ display: "flex", alignItems: "center" }}>
            {(userRole === "admin" || userRole === "ambassador") && (
              <Button
                variant="contained"
                color="primary"
                component={Link}
                to={`/group/${uuid}/invite`}
                sx={{ mr: 2 }}
              >
                Invite User
              </Button>
            )}
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
            {(userRole === "admin" ||
              userRole === "ambassador" ||
              userRole === "member") && (
              <Button
                variant="contained"
                color="primary"
                component={Link}
                to={`/group/${uuid}/create-post`}
                sx={{ ml: 2 }}
              >
                Create Post
              </Button>
            )}
          </Box>
        </Box>
        {group.description && (
          <Typography variant="body1" sx={{ mb: 2 }}>
            {group.description}
          </Typography>
        )}
        <Typography variant="body2" sx={{ mb: 2 }}>
          Created <DateComponent datetime={group.created_at} />
        </Typography>
        <Box sx={{ width: "100%", bgcolor: "background.paper", mb: 4 }}>
          {posts.map((post) => (
            <PostItem key={post.uuid} post={post} />
          ))}
        </Box>
        <Box sx={{ display: "flex", justifyContent: "center", width: "100%" }}>
          <Button
            variant="contained"
            color="primary"
            onClick={handleMore}
            disabled={next === null}
          >
            More
          </Button>
        </Box>
        {loading && <CircularProgress />}
      </Box>
    </Container>
  );
};

export default Group;
