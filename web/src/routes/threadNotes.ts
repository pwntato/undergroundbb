// The wording of a comment's byline and status lines -- #44. Pure, so it is
// tested without rendering. ThreadPanel shows it. Mirrors postNotes.ts, with the
// day taken from the comment's signed day.

import type { CommentView } from './runLoadThread'

export function commentAuthorLabel(comment: CommentView): string {
  return comment.authorName ?? 'an unknown member'
}

/** The status lines under a comment, strongest first. */
export function commentNotes(
  comment: CommentView,
): readonly { readonly tone: 'warn' | 'muted'; readonly text: string }[] {
  const who = commentAuthorLabel(comment)
  const notes: { tone: 'warn' | 'muted'; text: string }[] = []
  if (comment.content.kind === 'unreadable') {
    // The nonce is not signed, so a comment that does not open proves nothing
    // about its author; the wording blames no one.
    notes.push({
      tone: 'muted',
      text: 'This comment could not be opened. It may be damaged, or the key it needs may be out of reach.',
    })
    return notes
  }
  if (comment.signature.kind === 'invalid') {
    notes.push({
      tone: 'warn',
      text: `Signature check failed: this may not have been written by ${who}.`,
    })
  } else if (comment.signature.kind === 'unchecked') {
    notes.push({
      tone: 'muted',
      text: `Could not check who wrote this: ${comment.signature.reason}.`,
    })
  } else if (comment.keyAnchor === 'first-seen') {
    notes.push({
      tone: 'muted',
      text: `First time you have seen ${who}'s keys; they are saved now, so a later change will be caught.`,
    })
  }
  if (comment.content.timeSuspect) {
    notes.push({
      tone: 'warn',
      text: `Suspect: the time inside this comment does not match the day it was signed (${comment.signedDay}), so its time is not shown.`,
    })
  }
  return notes
}

/** "2026-10-28 14:03 UTC" from a comment's own time, or just the signed day when that time is not trusted. */
export function commentTimeLabel(comment: CommentView): string {
  if (comment.content.kind === 'opened' && !comment.content.timeSuspect) {
    return `${comment.content.at.slice(0, 10)} ${comment.content.at.slice(11, 16)} UTC`
  }
  return comment.signedDay
}
