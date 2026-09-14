// Editing /etc/tor/torrc without breaking anyone else's hidden services.
//
// torrc is a shared file. An operator running this beside a Dojo very likely
// already has hidden services defined there, and clobbering the file — or
// appending a duplicate HiddenServiceDir — breaks Tor for everything on the
// box, not just for us. So our block is delimited by markers: it can be found
// exactly, rewritten in place, and removed cleanly on uninstall, while every
// other line is passed through untouched.
//
// Pure string functions, deliberately: this is the logic most likely to damage
// something outside the project, so it is the logic most worth testing without
// touching a real system.

export const BEGIN_MARKER = '# >>> paynym-bot (managed) >>>'
export const END_MARKER = '# <<< paynym-bot (managed) <<<'

export type HiddenService = {
  /** Tor's key directory, e.g. /var/lib/tor/paynym-bot */
  dir: string
  /** Virtual port the onion answers on. 80 unless there is a reason. */
  virtualPort: number
  /** Local port the storefront listens on. */
  targetPort: number
}

export function renderBlock(svc: HiddenService): string {
  return [
    BEGIN_MARKER,
    '# Managed by paynym-bot. Edits between these markers are overwritten on',
    '# reinstall, and the whole block is removed by uninstall.sh --purge-onion.',
    `HiddenServiceDir ${svc.dir}`,
    `HiddenServicePort ${svc.virtualPort} 127.0.0.1:${svc.targetPort}`,
    END_MARKER,
  ].join('\n')
}

/** Does `contents` declare this HiddenServiceDir outside of our own block? */
export function hasUnmanagedService(contents: string, dir: string): boolean {
  const withoutOurs = removeBlock(contents)
  const wanted = dir.replace(/\/+$/, '')
  return withoutOurs
    .split('\n')
    .some((line) => {
      const m = line.trim().match(/^HiddenServiceDir\s+(\S+)/i)
      return m !== null && m[1].replace(/\/+$/, '') === wanted
    })
}

/**
 * Refuse to operate on a file whose markers are unbalanced.
 *
 * A BEGIN with no END (a truncated write, a hand edit, a partial restore) would
 * otherwise be read as "delete everything after", destroying other operators'
 * hidden services — on a Dojo host, its own API and Soroban onions. A damaged
 * torrc needs a human, not a heuristic.
 */
function assertBalancedMarkers(contents: string): void {
  const lines = contents.split('\n').map((l) => l.trim())
  const begins = lines.filter((l) => l === BEGIN_MARKER).length
  const ends = lines.filter((l) => l === END_MARKER).length
  if (begins === ends) return
  throw new Error(
    begins > ends
      ? 'torrc has a paynym-bot BEGIN marker with no matching END marker. Refusing to ' +
        'touch it: treating that as "delete to end of file" would remove other hidden ' +
        'services. Repair the block by hand (a .paynym-bot.bak may exist beside it).'
      : 'torrc has a paynym-bot END marker with no matching BEGIN marker. Refusing to ' +
        'touch a file whose managed block is damaged; repair it by hand first.',
  )
}

/** Strip our managed block, leaving everything else exactly as it was. */
export function removeBlock(contents: string): string {
  assertBalancedMarkers(contents)
  const lines = contents.split('\n')
  const out: string[] = []
  let inside = false
  for (const line of lines) {
    if (line.trim() === BEGIN_MARKER) {
      inside = true
      continue
    }
    if (line.trim() === END_MARKER) {
      inside = false
      continue
    }
    if (!inside) out.push(line)
  }
  // Collapse the blank gap the removal leaves behind, without reformatting
  // anything the operator wrote.
  return `${out.join('\n').replace(/\n{3,}/g, '\n\n').replace(/\s+$/, '')}\n`
}

/**
 * Add or update our hidden service. Idempotent: merging the same service twice
 * yields identical output, so re-running the installer is safe.
 *
 * Throws if the same HiddenServiceDir is already declared OUTSIDE our markers —
 * that is someone else's configuration (or a hand-edited earlier install), and
 * silently duplicating or overwriting it would be the wrong call to make on the
 * operator's behalf.
 */
export function mergeTorrc(contents: string, svc: HiddenService): string {
  if (hasUnmanagedService(contents, svc.dir)) {
    throw new Error(
      `torrc already declares HiddenServiceDir ${svc.dir} outside the paynym-bot ` +
        'markers. Remove that stanza (or point this install at a different ' +
        'directory) — refusing to duplicate or silently take it over.',
    )
  }
  const base = removeBlock(contents).replace(/\s+$/, '')
  const block = renderBlock(svc)
  return base.length > 0 ? `${base}\n\n${block}\n` : `${block}\n`
}
