import createApiClient from "./api_client";

const client = createApiClient("/api/groups");

export const createGroup = async (name, description) => {
  const data = await client("/create-group", "POST", { name, description });
  return data;
};

export const getGroupByUuid = async (groupUuid) => {
  const data = await client(`/group/${groupUuid}`);
  return data;
};

export const getUserRoleInGroup = async (groupUuid) => {
  const data = await client(`/group/${groupUuid}/role`);
  return data;
};

export const updateUserRoleInGroup = async (
  groupUuid,
  targetUserUuid,
  newRole
) => {
  const data = await client(`/group/${groupUuid}/update-role`, "POST", {
    targetUserUuid,
    newRole,
  });
  return data;
};

export const editGroup = async (
  groupUuid,
  name,
  description,
  hidden,
  trust_trace
) => {
  const data = await client(`/group/${groupUuid}`, "PUT", {
    name,
    description,
    hidden,
    trust_trace,
  });
  return data;
};

export const inviteUserToGroup = async (groupUuid, userUuid) => {
  const data = await client(`/group/${groupUuid}/invite`, "POST", { userUuid });
  return data;
};

export const getUsersInGroup = async (groupUuid) => {
  const data = await client(`/group/${groupUuid}/users`);
  return data;
};

export const getPostCountSinceLastLogin = async (groupUuid) => {
  const data = await client(`/group/${groupUuid}/recent-posts`);
  return data.postCount;
};
