import createApiClient from "./api_client";

const client = createApiClient("/api/posts");

export const createPost = async (title, body, groupId) => {
  const data = await client("/create-post", "POST", { title, body, groupId });
  return data;
};

export const getPosts = async (groupUuid, offset, parentId = null) => {
  const params = new URLSearchParams({ groupUuid, offset, parentId });
  const data = await client(`/posts?${params.toString()}`);
  return data;
};
