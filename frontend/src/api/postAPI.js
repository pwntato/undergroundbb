import createApiClient from "./api_client";

const client = createApiClient("/api/posts");

export const createPost = async (title, body, groupId, parentPostUuid = null) => {
  const data = await client("/create-post", "POST", { title, body, groupId, parentPostUuid });
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

export const deletePost = async (postUuid) => {
  const data = await client(`/post/${postUuid}`, "DELETE");
  return data;
};
