// A fingerprint laid out for reading aloud and comparing whole -- issue #65.
// The 60 digits come in twelve groups of five; this shows them four groups to a
// row, so a person reads row by row and checks every group rather than the first
// and last few characters. Each row is plain text with the hyphens kept, so a
// short value (or a copy) still reads as the value itself.

const GROUPS_PER_ROW = 4

export function FingerprintBlock({ value }: { readonly value: string }) {
  const groups = value.split('-')
  const rows: string[] = []
  for (let i = 0; i < groups.length; i += GROUPS_PER_ROW) {
    rows.push(groups.slice(i, i + GROUPS_PER_ROW).join('-'))
  }
  return (
    <div className="flex flex-col gap-0.5 font-mono text-sm tabular-nums">
      {rows.map((row, i) => (
        <span key={i}>{row}</span>
      ))}
    </div>
  )
}
