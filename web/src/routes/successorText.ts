// The sentences SuccessorPanel shows about a designation, kept apart from the
// component file so that one exports only components. #161.

import { formatDay, type AdminSuccessorStatus, type SuccessorOffer } from '@/lib/groups/designation'
import { memberLabel } from './memberLabel'

/** The sentence an admin reads about their standing designation, or the lack of one. */
export function adminStatusText(
  status: AdminSuccessorStatus,
  usernames?: ReadonlyMap<string, string>,
): string {
  const name = (id: string) => memberLabel(id, usernames)
  switch (status.kind) {
    case 'none':
      return 'You have not named a successor. If you stop logging in and you are the last admin, nobody will be able to govern this group.'
    case 'revoked':
      return `You revoked your successor on ${formatDay(status.day)}. You have no successor now.`
    case 'cancelled':
      return `You signed two designations on ${formatDay(status.day)}, which cancel each other. You have no successor now; designate again tomorrow.`
    case 'used':
      return `${name(status.claimedBy)} claimed the admin role you designated. Name a new successor if you want one.`
    case 'lapsed':
      return `Your designation of ${name(status.designation.successorUserId ?? '')} lapsed: your own role changed on ${formatDay(status.since)}. You have no successor now.`
    case 'successorGone':
      return `${name(status.designation.successorUserId ?? '')} is no longer a member, so your designation cannot be used. You have no successor now.`
    case 'successorAdmin':
      return `${name(status.designation.successorUserId ?? '')} is an admin now, so they cannot take over. You have no effective successor; name a member who is not an admin.`
    case 'active':
      return `${name(status.successorUserId)} is your successor. They can take over from ${formatDay(status.claimableFrom)} (${String(status.periodDays)} days after you named them), if neither you nor any other admin has logged in since then.`
  }
}

/** The lines a designated member reads about one offer. */
export function offerText(offer: SuccessorOffer, adminName: string): string {
  if (!offer.periodElapsed) {
    return `${adminName} named you as their successor on ${formatDay(offer.designationDay)}. You can claim the admin role from ${formatDay(offer.claimableFrom)} (UTC), ${String(offer.periodDays)} days after that, and only if they and every other admin have not logged in by then.`
  }
  return `${adminName} named you as their successor on ${formatDay(offer.designationDay)}, and ${String(offer.periodDays)} days have passed. If they and every other admin have not logged in since, you can claim the admin role now.`
}
