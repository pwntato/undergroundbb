import React from 'react';
import { Link } from 'react-router-dom';
import { Typography, Card, CardContent, CardActions, Button } from '@mui/material';

const PostItem = ({ post }) => {
  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="h5" component="div" gutterBottom>
          {post.title}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          <Link to={`/group/${post.group.uuid}`}>{post.group.name}</Link>
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          By <Link to={`/user/${post.author.uuid}`}>{post.author.username}</Link>
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {new Date(post.created_at).toLocaleString()}
        </Typography>
      </CardContent>
      <CardActions>
        <Button size="small" component={Link} to={`/post/${post.id}`}>
          Read More
        </Button>
      </CardActions>
    </Card>
  );
};

export default PostItem;
