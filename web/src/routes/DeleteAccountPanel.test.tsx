import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { MemoryRouter } from 'react-router'
import { renderToStaticMarkup } from 'react-dom/server'
import { DeleteAccountPanel, type DeletePanelState } from './DeleteAccountPanel'

const row = (groupId: string, label: string) => ({ groupId, label })

function render(
  state: DeletePanelState,
  extra: { confirming?: boolean; busy?: boolean } = {},
): string {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(DeleteAccountPanel, {
        state,
        confirming: extra.confirming ?? false,
        busy: extra.busy ?? false,
        onStart: () => undefined,
        onCancel: () => undefined,
        onConfirm: () => undefined,
      }),
    ),
  )
}

const ready = (over: Partial<Extract<DeletePanelState, { status: 'ready' }>> = {}) =>
  ({ status: 'ready', leaving: [], deleting: [], blockers: [], ...over }) as DeletePanelState

describe('DeleteAccountPanel', () => {
  it('shows only a Delete button until the user starts, so deleting is never one click', () => {
    const html = render(ready({ leaving: [row('g1', 'Book Club')] }))
    expect(html.match(/<button/g)).toHaveLength(1)
    expect(html).toContain('Delete my account')
    expect(html).toContain('Book Club')
    expect(html).not.toContain('Yes, delete')
  })

  it('says what cannot be undone, including what other members already read', () => {
    const html = render(ready())
    expect(html).toContain('can&#x27;t be undone')
    expect(html).toContain('already read')
  })

  it('names the groups that will be deleted outright', () => {
    const html = render(ready({ deleting: [row('g2', 'Solo Notes')] }))
    expect(html).toContain('These groups will be deleted')
    expect(html).toContain('Solo Notes')
  })

  it('offers no way to delete while a group blocks, and links to the group to fix it', () => {
    const html = render(ready({ blockers: [row('g3', 'Last Stand')] }))
    expect(html).toContain('Last Stand')
    expect(html).toContain('/groups/g3/members')
    expect(html).not.toContain('<button')
  })

  it('asks for confirmation, and locks the controls while running', () => {
    const open = render(ready(), { confirming: true })
    expect(open).toContain('Yes, delete my account')
    expect(open).toContain('Cancel')
    const busy = render(ready(), { confirming: true, busy: true })
    expect(busy.match(/disabled=""/g)).toHaveLength(2)
    expect(busy).toContain('Deleting')
  })

  it('renders loading and error states without any button', () => {
    expect(render({ status: 'loading' })).toContain('Checking your groups')
    const error = render({ status: 'error' })
    expect(error).toContain('nothing was changed')
    expect(error).not.toContain('<button')
  })

  it('says which fix applies to each blocking group', () => {
    const html = render(
      ready({
        blockers: [
          { groupId: 'g1', label: 'Last Stand', reason: 'needsSuccessor' },
          { groupId: 'g2', label: 'No Grant', reason: 'grantMissing' },
          { groupId: 'g3', label: 'Ghost Town', reason: 'noSuccessor' },
        ],
      }),
    )
    expect(html).toContain('make someone else an admin first')
    expect(html).toContain('isn&#x27;t on record')
    // Nobody can be promoted here, so promoting is not the advice.
    expect(html).toContain('Remove them from the members list first')
    // Removing them leaves a solo group, which the deletion then takes with it.
    expect(html).toContain('the group is then deleted with your account')
    expect(html.match(/make someone else an admin first/g)).toHaveLength(1)
  })

  it('does not claim nothing was changed when the re-check after a run fails', () => {
    const after = render({ status: 'error', afterRun: true })
    expect(after).toContain('Reload the page to see what is left')
    expect(after).not.toContain('nothing was changed')
  })
})
