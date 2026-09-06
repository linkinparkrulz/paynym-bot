// Turn the registry into the concrete set of addresses to watch.
//
// For each registered sender we watch a window of receive addresses starting at
// the sender's cursor (nextIndex) up to a gap limit. When an address is seen
// funded, credit it and advance the cursor. Address lookup is pluggable so this
// stays independent of how you talk to your own indexer (electrs, Bitcoin Core
// scantxoutset, etc.). Point it only at YOUR node over Tor — never a public
// explorer, since the watch list is your counterparty graph.

import type { PaynymIdentity } from './identity.ts'
import type { Registry } from './register.ts'

export const DEFAULT_GAP = 5

export type WatchAddress = {
  paymentCode: string
  index: number
  address: string
}

/**
 * Build the current watch window: the next `gap` indices per sender that are
 * not already known to be used.
 *
 * Known-used indices above the cursor are skipped rather than counted, so the
 * window always covers `gap` genuinely unused addresses. That keeps a customer
 * who pays out of order from shrinking the lookahead, and stops an
 * already-credited address being re-reported on every pass.
 */
export function watchWindow(
  identity: PaynymIdentity,
  registry: Registry,
  gap = DEFAULT_GAP,
): WatchAddress[] {
  const out: WatchAddress[] = []
  for (const rec of registry.all()) {
    const used = new Set(rec.usedAhead ?? [])
    let emitted = 0
    for (let i = rec.nextIndex; emitted < gap; i++) {
      if (used.has(i)) continue
      out.push({ paymentCode: rec.paymentCode, index: i, address: identity.receiveAddress(rec.paymentCode, i) })
      emitted++
    }
  }
  return out
}

/** A funded-address oracle backed by your own node. Returns true if used. */
export type UsedChecker = (address: string) => Promise<boolean>

export type Credit = WatchAddress & { spendKey: string }

/**
 * Scan the watch window once, crediting any used addresses and advancing
 * cursors so the window slides forward. Returns the credits found this pass.
 */
export async function scanOnce(
  identity: PaynymIdentity,
  registry: Registry,
  isUsed: UsedChecker,
  gap = DEFAULT_GAP,
): Promise<Credit[]> {
  const credits: Credit[] = []
  for (const w of watchWindow(identity, registry, gap)) {
    if (await isUsed(w.address)) {
      credits.push({ ...w, spendKey: identity.receivePrivateKey(w.paymentCode, w.index) })
      registry.advance(w.paymentCode, w.index)
    }
  }
  return credits
}
