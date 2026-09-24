// Pins PR #129 round 2's blocking finding: recovery's progress bar and
// label must not regress between the leading step (releasing) and the
// worker's own first event (recovering, before completeRecovery's upfront
// unwrap posts its progress event). No jsdom/RTL needed -- renderToStaticMarkup
// is enough to read the indicator's fill (encoded as a translateX% on its
// inline style, not an aria-valuenow -- see this file's own probe of
// components/ui/progress.tsx) and the visible label text.

import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { createElement } from 'react'
import { SignupProgressStep } from './SignupProgressStep'

/** The indicator's fill, as the percentage in its `translateX(-N%)` inline style. */
function fillPercent(html: string): number {
  const match = /transform:translateX\(-([\d.]+)%\)/.exec(html)
  const fill = match?.[1]
  if (fill === undefined) {
    throw new Error(`no translateX found in: ${html}`)
  }
  return 100 - Number(fill)
}

function labelText(html: string): string {
  const match = /<p class="text-sm text-muted-foreground">([^<]*)<\/p>/.exec(html)
  const label = match?.[1]
  if (label === undefined) {
    throw new Error(`no label paragraph found in: ${html}`)
  }
  return label
}

describe('SignupProgressStep', () => {
  it("recovery's fill and label never regress across releasing -> recovering -> resetting", () => {
    const props = {
      initialTotalSteps: 4,
      leadingStep: 'Confirming your code…',
      trailingStep: 'Saving your new credentials…',
      heading: 'Recovering your account',
      pendingLabel: 'Checking your recovery code…',
    }

    // releasing: currentStep='leading', no progress event yet.
    const releasing = renderToStaticMarkup(
      createElement(SignupProgressStep, { ...props, progress: null, currentStep: 'leading' }),
    )
    // recovering, before the worker's first event: no currentStep, progress still null.
    const recoveringPending = renderToStaticMarkup(
      createElement(SignupProgressStep, { ...props, progress: null }),
    )
    // recovering, after the unwrap's own progress event (step 1 of 4).
    const recoveringUnwrapped = renderToStaticMarkup(
      createElement(SignupProgressStep, {
        ...props,
        progress: {
          kind: 'signupProgress',
          id: 'x',
          step: 1,
          totalSteps: 4,
          label: 'Recovery code confirmed',
        },
      }),
    )
    // resetting: currentStep='trailing'.
    const resetting = renderToStaticMarkup(
      createElement(SignupProgressStep, {
        ...props,
        progress: {
          kind: 'signupProgress',
          id: 'x',
          step: 4,
          totalSteps: 4,
          label: 'Recovery verifier ready',
        },
        currentStep: 'trailing',
      }),
    )

    const fills = [releasing, recoveringPending, recoveringUnwrapped, resetting].map(fillPercent)
    let previous = -Infinity
    for (const [i, fill] of fills.entries()) {
      expect(fill, `fill dropped at phase ${i}: ${fills.join(' -> ')}`).toBeGreaterThanOrEqual(
        previous,
      )
      previous = fill
    }

    // The bar must hold at the leading step's own position (1 of 6 total:
    // leadingStep + 4 worker steps + trailingStep), not fall back to 0,
    // while nothing has been reported yet.
    expect(fillPercent(releasing)).toBeCloseTo((1 / 6) * 100, 1)
    expect(fillPercent(recoveringPending)).toBeCloseTo((1 / 6) * 100, 1)

    // The label must not revert to signup's own copy during that same gap.
    expect(labelText(recoveringPending)).toBe('Checking your recovery code…')
    expect(labelText(recoveringPending)).not.toBe('Generating your keys…')
  })

  it("signup's fill never regresses across generating -> loggingIn (workerStepOffset=0)", () => {
    const props = { heading: 'Setting up your account', trailingStep: 'Logging you in…' }

    const generatingPending = renderToStaticMarkup(
      createElement(SignupProgressStep, { ...props, progress: null }),
    )
    const generatingDone = renderToStaticMarkup(
      createElement(SignupProgressStep, {
        ...props,
        progress: {
          kind: 'signupProgress',
          id: 'x',
          step: 3,
          totalSteps: 3,
          label: 'Recovery verifier ready',
        },
      }),
    )
    const loggingIn = renderToStaticMarkup(
      createElement(SignupProgressStep, {
        ...props,
        progress: {
          kind: 'signupProgress',
          id: 'x',
          step: 3,
          totalSteps: 3,
          label: 'Recovery verifier ready',
        },
        currentStep: 'trailing',
      }),
    )

    const fills = [generatingPending, generatingDone, loggingIn].map(fillPercent)
    let previous = -Infinity
    for (const fill of fills) {
      expect(fill).toBeGreaterThanOrEqual(previous)
      previous = fill
    }
    // generatingDone must not already read 100%: #33's honest-progress
    // requirement this PR's own header comment cites -- the trailing login
    // derivation hasn't started yet.
    expect(fillPercent(generatingDone)).toBeLessThan(100)
  })
})
