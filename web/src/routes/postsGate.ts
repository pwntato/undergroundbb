// #43: which part of the posts screen is up -- the list, the password step, or
// the "you declined" notice. Kept apart from the component so the transitions
// can be tested without a DOM.
//
// The list is mounted only in `reading`. Mounting it loads page 1, and a cold
// tab's load asks for the password again, so mounting it while the user has just
// cancelled the password step would bring the prompt straight back.

export interface PostsGate {
  readonly step: 'reading' | 'password' | 'declined'
  /** Bumped after a re-login so the list remounts and loads from the first page. */
  readonly round: number
}

export type PostsGateEvent = 'coldKeys' | 'cancel' | 'askAgain' | 'reauthenticated'

export const INITIAL_POSTS_GATE: PostsGate = { step: 'reading', round: 0 }

export function nextPostsGate(gate: PostsGate, event: PostsGateEvent): PostsGate {
  switch (event) {
    case 'coldKeys':
      return gate.step === 'reading' ? { ...gate, step: 'password' } : gate
    case 'cancel':
      return gate.step === 'password' ? { ...gate, step: 'declined' } : gate
    case 'askAgain':
      return gate.step === 'declined' ? { ...gate, step: 'password' } : gate
    case 'reauthenticated':
      return gate.step === 'password' ? { step: 'reading', round: gate.round + 1 } : gate
  }
}
