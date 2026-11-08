import { describe, expect, it, vi } from 'vitest'
import { LogoutButton } from './LogoutButton'
import { elementsOf } from './elementTree.testkit'

function button(loggingOut: boolean, onLogout: () => Promise<void>) {
  const found = elementsOf(LogoutButton({ loggingOut, onLogout }))[0]
  if (found === undefined) throw new Error('LogoutButton rendered nothing')
  return found
}

describe('LogoutButton', () => {
  it('says "Log out" and is enabled when no logout is in flight', () => {
    const b = button(false, () => Promise.resolve())
    expect(b.props['children']).toBe('Log out')
    expect(b.props['disabled']).toBe(false)
  })

  it('is disabled while a logout is in flight, so a second click cannot send another', () => {
    expect(button(true, () => Promise.resolve()).props['disabled']).toBe(true)
  })

  it('calls the handler from its real onClick, once per click', () => {
    const onLogout = vi.fn().mockResolvedValue(undefined)
    const onClick = button(false, onLogout).props['onClick'] as () => void
    onClick()
    expect(onLogout).toHaveBeenCalledTimes(1)
    onClick()
    expect(onLogout).toHaveBeenCalledTimes(2)
  })
})
