import { describe, expect, it } from 'vitest'
import { INITIAL_POSTS_GATE, nextPostsGate, type PostsGate, type PostsGateEvent } from './postsGate'

function run(...events: PostsGateEvent[]): PostsGate {
  return events.reduce(nextPostsGate, INITIAL_POSTS_GATE)
}

describe('nextPostsGate', () => {
  it('asks for the password when the list finds the keys cold', () => {
    expect(run('coldKeys')).toEqual({ step: 'password', round: 0 })
  })

  it('stays on the notice after Cancel, with the list not mounted', () => {
    // The old screen went back to `reading` here, which remounted the list and re-asked.
    expect(run('coldKeys', 'cancel')).toEqual({ step: 'declined', round: 0 })
  })

  it('reopens the password step from the notice, and reloads the list only after a login', () => {
    expect(run('coldKeys', 'cancel', 'askAgain')).toEqual({ step: 'password', round: 0 })
    expect(run('coldKeys', 'cancel', 'askAgain', 'reauthenticated')).toEqual({
      step: 'reading',
      round: 1,
    })
  })

  it('ignores events that do not fit the step it is on', () => {
    expect(run('cancel')).toEqual(INITIAL_POSTS_GATE)
    expect(run('reauthenticated')).toEqual(INITIAL_POSTS_GATE)
    expect(run('coldKeys', 'coldKeys', 'cancel', 'coldKeys')).toEqual({
      step: 'declined',
      round: 0,
    })
  })
})
