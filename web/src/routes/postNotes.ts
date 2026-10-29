// The wording of a post's byline and status lines -- #43. Pure, so it is tested
// without rendering. GroupPostsPanel shows it.

import type { PostView } from './runListPosts'

/** The status lines under a post, strongest first. Pure, so the wording is testable. */
export function postNotes(
  post: PostView,
): readonly { readonly tone: 'warn' | 'muted'; readonly text: string }[] {
  const who = authorLabel(post)
  const notes: { tone: 'warn' | 'muted'; text: string }[] = []
  if (post.content.kind === 'unreadable') {
    // The nonce is not signed, so a post that does not open proves nothing about its
    // author; the wording blames no one.
    notes.push({
      tone: 'muted',
      text: 'This post could not be opened. It may be damaged, or the key it needs may be out of reach.',
    })
    return notes
  }
  if (post.signature.kind === 'invalid') {
    notes.push({
      tone: 'warn',
      text: `Signature check failed: this may not have been written by ${who}.`,
    })
  } else if (post.signature.kind === 'unchecked') {
    notes.push({
      tone: 'muted',
      text: `Could not check who wrote this: ${post.signature.reason}.`,
    })
  } else if (post.keyAnchor === 'first-seen') {
    notes.push({
      tone: 'muted',
      text: `First time you have seen ${who}'s keys; they are saved now, so a later change will be caught.`,
    })
  }
  if (post.content.timeSuspect) {
    notes.push({
      tone: 'warn',
      text: `Suspect: the time inside this post does not match the day it is filed under (${post.day}), so its time is not shown.`,
    })
  }
  return notes
}

export function authorLabel(post: PostView): string {
  return post.authorName ?? 'an unknown member'
}

/** "2026-10-28 14:03 UTC" from a post's own time, or just the filed day when that time is not trusted. */
export function postTimeLabel(post: PostView): string {
  if (post.content.kind === 'opened' && !post.content.timeSuspect) {
    return `${post.content.at.slice(0, 10)} ${post.content.at.slice(11, 16)} UTC`
  }
  return post.day
}
