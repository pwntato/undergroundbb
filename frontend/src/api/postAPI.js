import createApiClient from "./api_client";

const client = createApiClient("/api/posts");

export const createPost = async (title, body, groupId) => {
  const data = await client("/create-post", "POST", { title, body, groupId });
  return data;
};
