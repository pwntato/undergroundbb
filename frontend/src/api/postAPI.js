import createApiClient from "./api_client";

const client = createApiClient("/api/posts");

export const createPost = async (title, body, groupId, parentPostId = null) => {
  const data = await client("/create-post", "POST", { title, body, groupId, parentPostId });
  return data;
};

export const getPosts = async (groupUuid, offset, parentUuid = null) => {
  const params = new URLSearchParams({ groupUuid, offset, parentUuid: parentUuid });
  const data = await client(`/posts?${params.toString()}`);
  return data;
};

export const getPostByUuid = async (postUuid) => {
  const data = await client(`/post/${postUuid}`);
  return data;
};
