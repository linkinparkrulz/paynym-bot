// The always-online half of the receiver.
//
// Two independent jobs on timers:
//   listen — drain the Soroban inbox and register new customers,
//   scan   — check the watch window against the indexer and credit payments.
//
// There is no rendezvous republish timer: nothing is published any more, since
// the channel key is derived from the merchant's own payment code (see
// ./channel.ts). One fewer thing to keep alive.
//
// Every tick is guarded. A thrown timer callback would otherwise take the
// process down, and an indexer or Soroban node that is merely slow must not
// cause ticks to pile up on top of each other.

import { scanOnce } from './watcher.ts'
import type { Credit } from './watcher.ts'
import type { UsedChecker } from './watcher.ts'
import { MAX_SENDERS, UNPAID_TTL_MS } from './register.ts'
import type { PaynymIdentity } from './identity.ts'
import type { Registrar } from './register.ts'
import type { SorobanRPC } from './soroban.ts'

export const DEFAULT_POLL_INTERVAL_MS = 15_000
export const DEFAULT_SCAN_INTERVAL_MS = 60_000

export type DaemonDeps = {
  identity: PaynymIdentity
  registrar: Registrar
  rpc: SorobanRPC
  isUsed: UsedChecker
  /** Flush the registry to durable storage. Must not resolve until it is safe. */
  persist: () => Promise<void>
  gap?: number
  /** Concurrent address lookups per scan pass. See watcher.DEFAULT_CONCURRENCY. */
  concurrency?: number
  pollIntervalMs?: number
  scanIntervalMs?: number
  /** How long an unpaid registration is kept. See register.UNPAID_TTL_MS. */
  unpaidTtlMs?: number
  /**
   * Called for each newly credited payment. NOTE: a Credit carries the spend
   * key for that address. Do not log it, and do not send it anywhere.
   */
  onCredit?: (credit: Credit) => void
  onRegistered?: (paymentCode: string) => void
  log?: (line: string) => void
}

type Job = { name: string; intervalMs: number; run: () => Promise<void> }

export class Daemon {
  private readonly deps: DaemonDeps
  private readonly timers: NodeJS.Timeout[] = []
  private readonly running = new Set<string>()
  private stopped = false
  /** High-water mark of `Registrar.deferred()` already reported. */
  private lastDeferred = 0

  constructor(deps: DaemonDeps) {
    this.deps = deps
  }

  private log(line: string): void {
    ;(this.deps.log ?? console.log)(line)
  }

  /**
   * Drain the inbox once. State is persisted inside `onAccepted`, which
   * Registrar.poll awaits BEFORE removing the inbox entry — so a crash between
   * accepting a registration and recording it leaves the only copy in the
   * inbox, to be re-ingested next tick.
   */
  async pollOnce(): Promise<string[]> {
    // Reclaim room before draining, so a customer waiting on a full watch
    // list is admitted on this tick rather than the next one.
    await this.pruneOnce()

    const added = await this.deps.registrar.poll(this.deps.rpc, {
      onAccepted: async () => {
        await this.deps.persist()
      },
    })
    for (const paymentCode of added) {
      this.log(`registered customer ${paymentCode.slice(0, 12)}…`)
      this.deps.onRegistered?.(paymentCode)
    }
    // Report only what this tick deferred. `deferred()` is cumulative, so
    // logging it directly would repeat the same warning every 15s forever
    // once it had ever fired.
    const deferred = this.deps.registrar.deferred()
    if (deferred > this.lastDeferred) {
      this.log(
        `watch list is full (${MAX_SENDERS}); ` +
          `${deferred - this.lastDeferred} valid registration(s) left queued`,
      )
      this.lastDeferred = deferred
    }
    return added
  }

  /**
   * Drop registrations that have never been paid and are older than the TTL.
   * Persisted immediately: the pruned set must not come back on restart, or a
   * flood would be permanent.
   */
  async pruneOnce(): Promise<string[]> {
    const dropped = this.deps.registrar.registry.pruneUnpaid(
      this.deps.unpaidTtlMs ?? UNPAID_TTL_MS,
    )
    if (dropped.length > 0) {
      await this.deps.persist()
      this.log(`pruned ${dropped.length} registration(s) that were never paid`)
    }
    return dropped
  }

  /** Check the watch window once and credit anything that has been paid. */
  async scanOnce(): Promise<Credit[]> {
    const credits = await scanOnce(
      this.deps.identity,
      this.deps.registrar.registry,
      this.deps.isUsed,
      this.deps.gap,
      this.deps.concurrency,
    )
    if (credits.length > 0) {
      // Cursors moved, so record them before announcing anything.
      await this.deps.persist()
      for (const credit of credits) {
        // Deliberately does not log the credit object: it carries a spend key.
        this.log(`payment seen at index ${credit.index} (${credit.address})`)
        this.deps.onCredit?.(credit)
      }
    }
    return credits
  }

  private schedule(job: Job): void {
    const tick = async () => {
      if (this.stopped) return
      if (this.running.has(job.name)) {
        // The previous run is still going: skip rather than queue, so a slow
        // backend cannot build an unbounded backlog of overlapping work.
        return
      }
      this.running.add(job.name)
      try {
        await job.run()
      } catch (err) {
        // Never rethrow out of a timer: an unhandled rejection here would take
        // the whole receiver down over one transient backend failure.
        this.log(`${job.name} failed: ${(err as Error).message}`)
      } finally {
        this.running.delete(job.name)
      }
    }
    this.timers.push(setInterval(tick, job.intervalMs))
    void tick() // run immediately rather than waiting out the first interval
  }

  start(): void {
    this.stopped = false
    this.schedule({
      name: 'listen',
      intervalMs: this.deps.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
      run: () => this.pollOnce().then(() => undefined),
    })
    this.schedule({
      name: 'scan',
      intervalMs: this.deps.scanIntervalMs ?? DEFAULT_SCAN_INTERVAL_MS,
      run: () => this.scanOnce().then(() => undefined),
    })
  }

  stop(): void {
    this.stopped = true
    for (const timer of this.timers) clearInterval(timer)
    this.timers.length = 0
  }
}
