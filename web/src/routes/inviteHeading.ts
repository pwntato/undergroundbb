// The accept screen's heading. A public group's name comes with the invite
// (#155); a private group's does not, since it is ciphertext until the key
// arrives, so the heading stays generic.
export function inviteHeading(groupName: string | undefined): string {
  return groupName === undefined ? "You've been invited" : `You've been invited to ${groupName}`
}
