// The whole receiver loop, offline: register -> watch -> credit -> restart.
//
// Uses the in-memory Soroban node and a fake indexer, so this runs the same
// code path a live deployment does without a network.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PaynymIdentity } from '../src/identity.ts'
import { SorobanRPC } from '../src/soroban.ts'
import { Registrar, Registry, registerWithReceiver, inboxName } from '../src/register.ts'
import { scanOnce, watchWindow } from '../src/watcher.ts'
import { Daemon } from '../src/daemon.ts'
import { loadState, networkFor, newState, saveState } from '../src/state.ts'
import { memoryNode } from './memory-node.ts'
import type { UsedChecker } from '../src/watcher.ts'

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'))
const MERCHANT_SEED = fromHex('77'.repeat(64))
const CUSTOMER_SEED = fromHex('88'.repeat(64))
const NETWORK = networkFor('testnet')

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

/** A fake indexer: an address is "used" once it is added to this set. */
function fakeIndexer(paid: Set<string>): UsedChecker {
  return async (address: string) => paid.has(address)
}

const dir = mkdtempSync(join(tmpdir(), 'paynym-daemon-'))
const statePath = join(dir, 'state.json')

const merchant = PaynymIdentity.fromSeed(MERCHANT_SEED, NETWORK)
const customer = PaynymIdentity.fromSeed(CUSTOMER_SEED, NETWORK)

const node = memoryNode()
const rpc = new SorobanRPC(node.transport)
const paid = new Set<string>()

function buildDaemon(registry: Registry) {
  const state = newState('testnet')
  const registrar = new Registrar(merchant, registry)
  const daemon = new Daemon({
    identity: merchant,
    registrar,
    rpc,
    isUsed: fakeIndexer(paid),
    persist: async () => saveState(statePath, { ...state, senders: registry.toJSON() }),
    log: () => {}, // quiet in tests
  })
  return { daemon, registrar, registry }
}

await (async () => {
  const { daemon, registry } = buildDaemon(new Registry())

  // --- register --------------------------------------------------------------
  await registerWithReceiver(rpc, customer, merchant.paymentCode())
  const added = await daemon.pollOnce()
  assert('daemon registers the customer', added.length === 1 && added[0] === customer.paymentCode())
  assert('inbox drained', node.live(inboxName(merchant.paymentCode())).length === 0)

  const persisted = loadState(statePath)
  assert('registration was persisted', persisted.senders.length === 1)
  assert('persisted code matches', persisted.senders[0].paymentCode === customer.paymentCode())

  // --- nothing paid yet ------------------------------------------------------
  assert('no credits before payment', (await daemon.scanOnce()).length === 0)

  // --- the customer pays, out of order --------------------------------------
  // They skip to index 2. A cursor that jumped to 3 here would abandon 0 and 1,
  // and the payment to index 0 below would never be watched for.
  const addr2 = customer.sendAddress(merchant.paymentCode(), 2)
  paid.add(addr2)

  const credits2 = await daemon.scanOnce()
  assert('credits the out-of-order payment', credits2.length === 1 && credits2[0].index === 2)
  assert('merchant derived the same address', credits2[0].address === addr2)
  assert('cursor does NOT jump past the gap', registry.get(customer.paymentCode())!.nextIndex === 0)

  const windowAfter = watchWindow(merchant, registry)
  assert('index 0 is still watched', windowAfter.some((w) => w.index === 0))
  assert('the credited index is not re-watched', !windowAfter.some((w) => w.index === 2))
  assert('the window still offers a full lookahead', windowAfter.length === 5)

  // Re-scanning must not double-credit an address already accounted for.
  assert('no double credit on re-scan', (await daemon.scanOnce()).length === 0)

  // --- now they pay index 0, behind the earlier one -------------------------
  const addr0 = customer.sendAddress(merchant.paymentCode(), 0)
  paid.add(addr0)
  const credits0 = await daemon.scanOnce()
  assert('credits a payment behind the highest seen', credits0.length === 1 && credits0[0].index === 0)
  assert('cursor advances only across the contiguous run',
    registry.get(customer.paymentCode())!.nextIndex === 1)

  // --- restart ---------------------------------------------------------------
  // A fresh process, rebuilt from the state file alone, must watch exactly the
  // same addresses. Receive keys are not derivable from the seed without these
  // customer payment codes.
  const restored = Registry.fromJSON(loadState(statePath).senders)
  const before = watchWindow(merchant, registry).map((w) => w.address).join(',')
  const after = watchWindow(merchant, restored).map((w) => w.address).join(',')
  assert('restart reproduces the identical watch window', before === after && before.length > 0)

  // --- persistence failure keeps the registration recoverable ---------------
  const other = PaynymIdentity.fromSeed(fromHex('99'.repeat(64)), NETWORK)
  await registerWithReceiver(rpc, other, merchant.paymentCode())
  const failing = new Daemon({
    identity: merchant,
    registrar: new Registrar(merchant, new Registry()),
    rpc,
    isUsed: fakeIndexer(paid),
    persist: async () => {
      throw new Error('disk full')
    },
    log: () => {},
  })
  let threw = false
  try {
    await failing.pollOnce()
  } catch {
    threw = true
  }
  assert('a failed persist propagates', threw)
  assert('the registration survives in the inbox',
    node.live(inboxName(merchant.paymentCode())).length === 1)

  // --- guarded ticks ---------------------------------------------------------
  // A backend that throws must not take the process down or stop the timers.
  const brokenLines: string[] = []
  const broken = new Daemon({
    identity: merchant,
    registrar: new Registrar(merchant, new Registry()),
    rpc: new SorobanRPC(async () => {
      throw new Error('soroban unreachable')
    }),
    isUsed: async () => false,
    persist: async () => {},
    pollIntervalMs: 20,
    scanIntervalMs: 20,
    log: (l) => brokenLines.push(l),
  })
  broken.start()
  await new Promise((r) => setTimeout(r, 120))
  broken.stop()
  assert('a failing backend is logged, not fatal', brokenLines.some((l) => l.includes('failed')))
  assert('ticks kept running after failures', brokenLines.length >= 2)
})()

// --- the watch list is bounded, and a flood does not become permanent -------
//
// Registration is open by design and payment codes are free to generate, so
// the watch list is an unauthenticated write and needs a ceiling. Past that
// ceiling a valid registration must NOT be silently dropped — it is left in
// the inbox to be admitted once room appears, because it may be a real
// customer rather than a flood.
await (async () => {
  const node2 = memoryNode()
  const rpc2 = new SorobanRPC(node2.transport)
  const capped = new Registry(1) // capacity of one, so the cap is reachable
  const registrar = new Registrar(merchant, capped)

  const first = PaynymIdentity.fromSeed(fromHex('11'.repeat(64)), NETWORK)
  const second = PaynymIdentity.fromSeed(fromHex('22'.repeat(64)), NETWORK)
  await registerWithReceiver(rpc2, first, merchant.paymentCode())
  await registerWithReceiver(rpc2, second, merchant.paymentCode())

  const added = await registrar.poll(rpc2)
  assert('only the first registration fits under the cap', added.length === 1)
  assert('the watch list stopped at the cap', capped.size() === 1)
  assert('the one that did not fit was counted, not lost', registrar.deferred() === 1)
  assert(
    'and it is still in the inbox, awaiting room',
    (await rpc2.list(inboxName(merchant.paymentCode()))).length === 1,
  )

  // Pruning is what makes room. The admitted customer has never been paid, so
  // it is eligible once it is old enough — and the queued one is then taken.
  const later = Date.now() + 31 * 24 * 60 * 60 * 1000
  const dropped = capped.pruneUnpaid(30 * 24 * 60 * 60 * 1000, later)
  assert('an unpaid registration is prunable once stale', dropped.length === 1)
  const admitted = await registrar.poll(rpc2)
  assert('the queued registration is admitted after the prune', admitted.length === 1)
  assert('and the inbox is finally drained', (await rpc2.list(inboxName(merchant.paymentCode()))).length === 0)
})()

// --- a paid registration is never pruned -----------------------------------
// This is the line that must not move: a sender with any payment history holds
// the only route back to money that has already arrived.
await (async () => {
  const reg = new Registry()
  reg.add(customer.paymentCode(), undefined, 1)
  reg.advance(customer.paymentCode(), 0) // one payment seen
  const dropped = reg.pruneUnpaid(1, Date.now())
  assert('a sender that has been paid survives pruning', dropped.length === 0)
  assert('and is still registered', reg.has(customer.paymentCode()))

  const unpaid = new Registry()
  unpaid.add('PM8T-never-paid', undefined, 1)
  assert('an unpaid sender of the same age is pruned', unpaid.pruneUnpaid(1, Date.now()).length === 1)
})()

// --- the scan fits in a tick -------------------------------------------------
//
// The lookups are independent round trips; run serially, a real shop's watch
// list does not fit in a scan interval. Assert both halves of the fix: the
// lookups overlap, and the addresses are not re-derived from scratch each pass
// (a BIP47 address costs an ECDH, and the window is rebuilt every tick).
await (async () => {
  const many = new Registry()
  for (let i = 0; i < 20; i++) {
    many.add(PaynymIdentity.fromSeed(fromHex(String(i + 10).repeat(32)), NETWORK).paymentCode())
  }
  const window = watchWindow(merchant, many)
  assert('the window covers every sender', window.length === 100)

  let inFlight = 0
  let peak = 0
  const slowOracle: UsedChecker = async () => {
    inFlight++
    peak = Math.max(peak, inFlight)
    await new Promise((r) => setTimeout(r, 5))
    inFlight--
    return false
  }

  const t0 = Date.now()
  await scanOnce(merchant, many, slowOracle)
  const cold = Date.now() - t0
  assert('lookups overlap rather than running one at a time', peak > 1)
  assert('and stay bounded, not all at once', peak <= 6)
  assert(`a 100-address window beats serial (${cold}ms vs ${100 * 5}ms)`, cold < 100 * 5)

  // Second pass: derivation is memoised, so the pass costs only its round
  // trips. With 6-way concurrency that is ~100/6 * 5ms.
  const t1 = Date.now()
  await scanOnce(merchant, many, slowOracle)
  const warm = Date.now() - t1
  assert(`a warm pass is close to pure latency (${warm}ms)`, warm < 200)
})()

rmSync(dir, { recursive: true, force: true })

console.log('')
if (failures === 0) {
  console.log('PASS — daemon loop: register, watch, credit, restart.')
} else {
  console.log(`FAIL — ${failures} daemon check(s) failed.`)
  process.exit(1)
}
