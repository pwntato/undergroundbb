// #33: "recovery code, presented so it cannot be skimmed... the one screen
// in the product a user must not click past, and nothing may compete with
// it for attention."
//
// Two things enforce that here, deliberately beyond a plain "I saved it"
// checkbox: (1) nothing else on the page is interactive except a copy
// button and the acknowledgment control itself -- no skip link, no back
// button competing for a rushed click; (2) the Continue button stays
// disabled until the checkbox is explicitly checked, so the only way past
// this screen is an affirmative action naming what it confirms, not a
// default-enabled button someone habitually clicks through.
//
// The code itself is never sent anywhere from this screen -- it was
// generated in the crypto worker (recovery-code.ts) and is only ever POSTed
// to the server as an input to recovery, never stored there in the clear.

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

export function RecoveryCodeStep({
  recoveryCode,
  onAcknowledged,
}: {
  recoveryCode: string
  onAcknowledged: () => void
}) {
  const [acknowledged, setAcknowledged] = useState(false)
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    void navigator.clipboard
      .writeText(recoveryCode)
      .then(() => {
        setCopied(true)
      })
      .catch(() => {
        // Clipboard access can be denied (permissions, insecure context) --
        // the code is still selectable text on the page either way, so this
        // is not fatal to completing signup.
      })
  }

  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Save your recovery code</CardTitle>
          <CardDescription>
            This is the only way back into your account if you forget your password. Nobody -- not
            even us -- can recover it for you if you lose it.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div
            role="textbox"
            aria-readonly="true"
            aria-label="Your recovery code"
            className="select-all rounded-md border bg-muted px-4 py-3 text-center font-mono text-lg tracking-wide"
          >
            {recoveryCode}
          </div>
          <Button type="button" variant="outline" onClick={handleCopy}>
            {copied ? 'Copied' : 'Copy code'}
          </Button>
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={acknowledged}
              onChange={(e) => {
                setAcknowledged(e.target.checked)
              }}
            />
            <span>I&apos;ve saved this recovery code somewhere safe.</span>
          </label>
        </CardContent>
      </Card>
      <Button type="button" disabled={!acknowledged} onClick={onAcknowledged}>
        Continue
      </Button>
    </div>
  )
}
