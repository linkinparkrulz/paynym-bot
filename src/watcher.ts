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

/**
 * How many address lookups a scan pass runs at once.
 *
 * The lookups are independent, and each one is a round trip to the indexer —
 * over Tor that is most of a second, which is why the Electrum client allows
 * 30s per request. Run serially, a real shop's watch list does not fit in a
 * scan interval: 100 customers is 500 sequential round trips, and the daemon
 * skips an overlapping tick rather than queueing, so the scan silently falls
 * behind and payments go unnoticed. That is the failure this bounds.
 *
 * Bounded rather than unlimited because the other end is the operator's own
 * single Dojo, not a service to be hammered.
 */
export const DEFAULT_CONCURRENCY = 6

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
 * cursors so the window slides forward. Returns the credits found this pass,
 * in watch-window order.
 *
 * Lookups run `concurrency` at a time; the cursor updates happen afterwards,
 * in window order, so the result and the resulting registry state do not
 * depend on which round trip finished first. `Registry.advance` is
 * order-independent in any case — it tracks used indices in a set and only
 * moves the cursor across a contiguous run — but determinism here is what
 * makes the daemon's behaviour reproducible from the state file alone.
 */
export async function scanOnce(
  identity: PaynymIdentity,
  registry: Registry,
  isUsed: UsedChecker,
  gap = DEFAULT_GAP,
  concurrency = DEFAULT_CONCURRENCY,
): Promise<Credit[]> {
  const window = watchWindow(identity, registry, gap)
  const used = new Array<boolean>(window.length)

  // A fixed pool of workers pulling from a shared cursor: no batching, so one
  // slow lookup cannot idle the rest of the pool behind it.
  let next = 0
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++
      if (i >= window.length) return
      used[i] = await isUsed(window[i]!.address)
    }
  }
  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(concurrency, window.length)) }, worker),
  )

  const credits: Credit[] = []
  for (let i = 0; i < window.length; i++) {
    if (!used[i]) continue
    const w = window[i]!
    credits.push({ ...w, spendKey: identity.receivePrivateKey(w.paymentCode, w.index) })
    registry.advance(w.paymentCode, w.index)
  }
  return credits
}
