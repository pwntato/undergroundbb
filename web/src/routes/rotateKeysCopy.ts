// The text and the password rule behind the "Rotate keys" screen (#62), kept
// out of the component so they can be tested and so oxlint's
// only-export-components rule has nothing to object to.

import type { KeyRotationFailure, KeyRotationStep } from './runKeyRotation'

/** Same floor as signup and change-password: it only stops an accidental empty submit. */
export const MIN_PASSWORD_LENGTH = 8

/** The first problem with the new password and its confirmation, or null. */
export function validateNewPassword(password: string, confirm: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`
  }
  if (password !== confirm) {
    return 'Passwords do not match.'
  }
  return null
}

function groupList(groups: readonly string[], labelFor: (groupId: string) => string): string {
  return groups.length === 0 ? 'a group' : groups.map(labelFor).join(', ')
}

/** What to tell the user about a rotation that did not finish. */
export function failureMessage(
  failure: KeyRotationFailure,
  labelFor: (groupId: string) => string,
): string {
  switch (failure.kind) {
    case 'needsLogin':
      return 'Your keys are not loaded in this tab, so it cannot rotate them. Log in again, then come back here.'
    case 'authRequired':
      return 'Your session has expired. Log in again, then come back here.'
    case 'cooldown':
      return 'You rotated your keys recently. Keys can be rotated once a day, so try again tomorrow.'
    case 'handoffPending':
      return `A key change you started earlier is still waiting to finish in ${groupList(failure.groups, labelFor)}. Let that finish first.`
    case 'groupBusy':
      return `Another admin's key change is still under way in ${groupList(failure.groups, labelFor)}. Wait for it to finish, then try again.`
    case 'changedElsewhere':
      return 'Your account changed while this was in progress, for example in another tab or by a password change. Nothing was rotated. Reload this page and try again.'
    case 'rejected':
      return `The server refused the rotation: ${failure.message} Nothing was rotated.`
    case 'expired':
      return 'This attempt took too long and has expired. Your keys have not changed. Choose your new password again to start over.'
    case 'unreachable':
      return "We couldn't reach the server, and your keys have not changed. Check your connection and try again."
    case 'unconfirmed':
      return "We couldn't confirm whether your keys were rotated. If they were, the new password you just chose and the recovery code below are the ones that work, so write the code down now. Trying again checks first and never rotates twice."
  }
}

/** The line shown while a rotation runs. */
export function stepText(step: KeyRotationStep): string {
  switch (step.name) {
    case 'preparing':
      return 'Preparing your new keys…'
    case 'handoffs':
      return step.total === 0
        ? 'Checking your groups…'
        : `Saving each group's key for your new keys (${step.done} of ${step.total})…`
    case 'signing':
      return 'Signing the change with your old and new keys…'
    case 'settling':
      return 'Making sure the earlier attempt did not go through. This takes about a minute…'
    case 'committing':
      return 'Saving your new keys…'
  }
}
