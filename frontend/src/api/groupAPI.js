import createApiClient from "./api_client";

const client = createApiClient("/api/groups");

export const createGroup = async (name, description) => {
  const data = await client("/create-group", "POST", { name, description });
  return data;
};

export const getGroupByUuid = async (uuid) => {
  const data = await client(`/group/${uuid}`);
  return data;
};
