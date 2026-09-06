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
import { watchWindow } from '../src/watcher.ts'
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

rmSync(dir, { recursive: true, force: true })

console.log('')
if (failures === 0) {
  console.log('PASS — daemon loop: register, watch, credit, restart.')
} else {
  console.log(`FAIL — ${failures} daemon check(s) failed.`)
  process.exit(1)
}
