// The text and the password rule behind the "Rotate keys" screen (#62), kept
// out of the component so they can be tested and so oxlint's
// only-export-components rule has nothing to object to.

import { describeRotation } from './runRotation'
import type { KeyRotationFailure, KeyRotationStep } from './runKeyRotation'
import type { SelfRekeyOutcome } from './runSelfRekey'

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
      return `A key change you started earlier is still waiting to finish re-keying ${groupList(failure.groups, labelFor)}. That step is not available in this version yet and will finish in a later update; nothing needs doing now, and keys cannot be rotated again until then.`
    case 'groupBusy':
      return `Another admin's key change is still under way in ${groupList(failure.groups, labelFor)}. Wait for it to finish, then try again.`
    case 'changedElsewhere':
      return 'Your account changed while this was in progress, for example in another tab or by a password change. Nothing was rotated. Reload this page and try again.'
    case 'rejected':
      return `The server refused the rotation: ${failure.message} Nothing was rotated.`
    case 'expired':
      return "This attempt has expired, either because it sat for too long or because this device's date or time is wrong. Check that they are correct, then choose your new password again. Your keys have not changed."
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
      return 'Making sure the earlier attempt did not go through. This takes about a minute; stay on this page…'
    case 'committing':
      return 'Saving your new keys…'
  }
}

/** The line above "Finish key changes": what the button can and cannot do yet. */
export function pendingRekeyText(
  groups: readonly string[],
  labelFor: (groupId: string) => string,
): string {
  return `A key change you started earlier still has to re-key ${groupList(groups, labelFor)}. Finishing works for groups where you are the only member; groups with other members finish in a later update. Keys cannot be rotated again until then.`
}

/** One line per group for the result of finishing a key change (#62). */
export function selfRekeyText(
  outcome: SelfRekeyOutcome,
  label: string,
  userLabel: (userId: string) => string,
): string {
  switch (outcome.status) {
    case 'rekeyed': {
      const note = describeRotation(outcome.rotation, userLabel)
      return note === null ? `${label}: your new keys are in place.` : `${label}: ${note.text}`
    }
    case 'stale':
      return `${label}: the group moved on before this finished, so the saved key was no longer needed. Another admin can approve your new keys there.`
    case 'not-admin':
      return `${label}: you are no longer an admin there, so there is nothing to finish.`
    case 'open':
      return `${label}: this group cannot be re-keyed, and finishing it for an open group is not available yet.`
    case 'waiting':
      return `${label}: this group has other members, and finishing it for them is not available yet. Nothing was changed; it will finish in a later update.`
    case 'incomplete':
      return `${label}: stopped (${outcome.reason}). Try again.`
  }
}
