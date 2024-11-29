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

export const getUserRoleInGroup = async (uuid) => {
  const data = await client(`/group/${uuid}/role`);
  return data;
};

export const editGroup = async (uuid, name, description, hidden, trust_trace) => {
  const data = await client(`/group/${uuid}`, "PUT", { name, description, hidden, trust_trace });
  return data;
};
