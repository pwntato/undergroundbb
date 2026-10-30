// #43: what the posts screen shows after the user cancels the password step.
// Prop-driven, so it can be tested with renderToStaticMarkup (see
// GroupPostsPanel.tsx's header). It must offer a way off the page: there is no
// app-wide navigation, so without the link the browser's Back button is the
// only exit.

import { Link } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

export function PostsPasswordDeclined({
  message,
  onAskAgain,
}: {
  readonly message: string
  readonly onAskAgain: () => void
}) {
  return (
    <div className="flex w-full max-w-xl flex-col gap-4 text-left">
      <Alert variant="destructive">
        <AlertDescription>{message}</AlertDescription>
      </Alert>
      <Button type="button" variant="outline" onClick={onAskAgain}>
        Enter password
      </Button>
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </div>
  )
}
