// How far this device's clock is from the server's -- #341. A device clock that runs behind
// can make a claim look too early ("You can claim from <date>") on the very day the server
// already accepts it, and the server cannot say so: it only ever sees the day the device
// chose. The API's own `Date` header is the one place the client can read the server's time.
//
// Every API answer updates the estimate, so the last one is as fresh as the last call. A
// caller that needs a current reading makes an API call first (the claim reloads the group).
// The header has one-second resolution and includes the trip time, which is nothing against
// the two-hour window this is used for.

let offsetMs: number | undefined

/**
 * Records the server's time from a response, unless the answer came out of a cache. Never
 * throws: a clock estimate must not be able to break the API call it rode in on.
 */
export function noteServerDate(
  res: { readonly headers: { get(name: string): string | null } },
  deviceNowMs: number = Date.now(),
): void {
  try {
    // A cached answer carries the Date of when it was stored, not the time now.
    if (res.headers.get('age') !== null) return
    const header = res.headers.get('date')
    if (header === null) return
    const serverMs = Date.parse(header)
    if (Number.isNaN(serverMs)) return
    offsetMs = serverMs - deviceNowMs
  } catch {
    // No headers to read (a response without them): keep the estimate as it was.
  }
}

/** The server's current time as best known (ms since the epoch), or undefined before any answer. */
export function serverNowMs(deviceNowMs: number = Date.now()): number | undefined {
  return offsetMs === undefined ? undefined : deviceNowMs + offsetMs
}

/** Forgets the estimate, for tests. */
export function forgetServerClock(): void {
  offsetMs = undefined
}
