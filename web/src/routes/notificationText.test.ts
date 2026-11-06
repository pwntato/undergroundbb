import { describe, expect, it } from 'vitest'
import { notificationHref, notificationText } from './notificationText'

describe('notificationText', () => {
  it('names the actor, the kind, what it landed on and the group', () => {
    expect(notificationText({ kind: 'reply', cmtPath: '0001' }, 'alice', 'Roof Group')).toBe(
      'alice replied to your comment in Roof Group',
    )
    expect(notificationText({ kind: 'reply', cmtPath: '0000' }, 'alice', 'Roof Group')).toBe(
      'alice replied to your post in Roof Group',
    )
    expect(notificationText({ kind: 'reaction', cmtPath: '0000' }, 'bob', 'Book Club')).toBe(
      'bob reacted to your post in Book Club',
    )
    expect(notificationText({ kind: 'reaction', cmtPath: '0002.0001' }, 'bob', 'Book Club')).toBe(
      'bob reacted to your comment in Book Club',
    )
  })

  it('says Someone for an actor that did not resolve or was deleted', () => {
    expect(notificationText({ kind: 'reply', cmtPath: '0000' }, undefined, 'G')).toBe(
      'Someone replied to your post in G',
    )
    expect(notificationText({ kind: 'reply', cmtPath: '0000' }, '', 'G')).toBe(
      'Someone replied to your post in G',
    )
  })
})

describe('notificationHref', () => {
  it('links to the thread with the post id encoded the way the posts list does', () => {
    const postId = 'a'.repeat(8) + '#2026-10-28#00112233445566a1'
    expect(notificationHref({ groupId: 'g1', postId })).toBe(
      `/groups/g1/posts/${encodeURIComponent(postId)}`,
    )
    expect(notificationHref({ groupId: 'g1', postId })).toContain('%23')
  })
})
