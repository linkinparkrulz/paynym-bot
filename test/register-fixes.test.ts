// Regression tests for defects a one-shot test cannot see, but that become
// certain failures once the receiver runs continuously.
//
// A2: two customers register back to back with no publish tick in between.
//   Both must succeed. This once failed because the merchant published a
//   rendezvous key that the first customer's read CONSUMED. There is no
//   published key any more, so the failure mode is structurally gone — this
//   test pins that it stays gone.
//
// A3: a crash between accepting a registration and removing its inbox entry
//   must lose nothing.
//
// Restart: the merchant needs no secret beyond the seed to decrypt. The channel
//   key comes from its own payment code, so there is no separate box keypair
//   left to fail to persist.
//
// Substitution: an attacker who knows the merchant's (public) payment code, and
//   who can write to the inbox directory, still cannot read a registration.
//
// Test-double fidelity: the in-memory node must model Remove faithfully, or the
//   assertions above pass without demonstrating anything.
//
// Testnet: payment-code derivation must be network-independent.

import { PaynymIdentity } from '../src/identity.ts'
import { TESTNET } from '../src/bip47.ts'
import { SorobanRPC } from '../src/soroban.ts'
import { sealToPaymentCode } from '../src/channel.ts'
import { watchWindow } from '../src/watcher.ts'
import {
  Registrar,
  Registry,
  registerWithReceiver,
  buildRegisterEnvelope,
  inboxName,
} from '../src/register.ts'
import { memoryNode, MODE_TTL_MS } from './memory-node.ts'

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'))

const ALICE_SEED = fromHex(
  '64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a',
)
const BOB_SEED = fromHex(
  '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110',
)
const CAROL_SEED = fromHex('02'.repeat(32))
const MALLORY_SEED = fromHex('66'.repeat(64))

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

await (async () => {
  // --- A2: two customers, no publish tick in between ------------------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const carol = PaynymIdentity.fromSeed(CAROL_SEED)
    const registrar = new Registrar(bob, new Registry())

    const aPosted = await registerWithReceiver(rpc, alice, bob.paymentCode())
    const bPosted = await registerWithReceiver(rpc, carol, bob.paymentCode())
    assert('A2: both customers posted', aPosted && bPosted)

    const added = await registrar.poll(rpc)
    assert('A2: both customers registered', added.length === 2)
    assert('A2: alice in registry', registrar.registry.has(alice.paymentCode()))
    assert('A2: carol in registry', registrar.registry.has(carol.paymentCode()))
  }

  // --- A3: crash between accept and remove ----------------------------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const inbox = inboxName(bob.paymentCode())

    const registrar = new Registrar(bob, new Registry())
    await registerWithReceiver(rpc, alice, bob.paymentCode())

    let threw = false
    try {
      await registrar.poll(rpc, {
        onAccepted: async () => {
          throw new Error('disk full')
        },
      })
    } catch {
      threw = true
    }
    assert('A3: onAccepted failure propagates', threw)
    assert('A3: inbox entry survives the crash', node.live(inbox).length === 1)

    // "Restart": a fresh Registrar built from the same seed. Nothing else was
    // persisted, because onAccepted threw.
    const restarted = new Registrar(PaynymIdentity.fromSeed(BOB_SEED), new Registry())
    const added = await restarted.poll(rpc)
    assert('A3: registration picked up on restart', added.length === 1 && added[0] === alice.paymentCode())
    assert('A3: inbox entry finally removed', node.live(inbox).length === 0)
    assert('A3: re-poll registers nothing new', (await restarted.poll(rpc)).length === 0)
  }

  // --- Restart needs nothing but the seed -----------------------------------
  // The channel key is derived from the merchant's own payment code, so an
  // in-flight registration posted before a restart still decrypts after it.
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)

    await registerWithReceiver(rpc, alice, bob.paymentCode())

    const restarted = new Registrar(PaynymIdentity.fromSeed(BOB_SEED), new Registry())
    const added = await restarted.poll(rpc)
    assert('seed alone decrypts an in-flight registration', added.length === 1 && added[0] === alice.paymentCode())
  }

  // --- Substitution: writing to the inbox buys an attacker nothing ----------
  // Mallory knows Bob's payment code (it is published on his onion page) and
  // can write to his inbox directory, since customers must be able to. Neither
  // lets her read a registration: it is sealed to Bob's child-0 key, and there
  // is no published rendezvous key to replace with her own.
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const mallory = PaynymIdentity.fromSeed(MALLORY_SEED)
    const inbox = inboxName(bob.paymentCode())

    // Mallory pollutes the inbox with a key of her own, the old attack shape.
    await rpc.add(inbox, sealToPaymentCode(mallory.paymentCode(), 'pick me'), 'long')
    await registerWithReceiver(rpc, alice, bob.paymentCode())

    const entries = node.live(inbox)
    const asMallory = new Registrar(mallory, new Registry())
    const readByMallory = entries.map((e) => asMallory.ingest(e)).filter(Boolean)
    assert("substitution: attacker reads no customer's payment code", readByMallory.length === 0)

    const registrar = new Registrar(bob, new Registry())
    const added = await registrar.poll(rpc)
    assert('substitution: merchant still registers the real customer', added.length === 1)
    assert('substitution: attacker entry counted as rejected', registrar.rejected() === 1)
  }

  // --- A failed persist must not lose the customer -------------------------
  // The A3 case above builds a FRESH Registrar after the throw, which quietly
  // simulates a process restart the daemon never performs. The daemon keeps one
  // long-lived Registrar, so an in-memory add that outlives a failed persist
  // makes the next tick believe the customer is already known — skipping
  // persistence and then deleting the only durable copy.
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const inbox = inboxName(bob.paymentCode())

    const registrar = new Registrar(bob, new Registry())
    await registerWithReceiver(rpc, alice, bob.paymentCode())

    const persisted: string[] = []
    try {
      await registrar.poll(rpc, {
        onAccepted: async () => {
          throw new Error('disk full')
        },
      })
    } catch {
      /* expected */
    }
    assert('retry: entry survives the failed tick', node.live(inbox).length === 1)

    // Same process, same Registrar, persistence working again.
    const added = await registrar.poll(rpc, {
      onAccepted: async (pc) => {
        persisted.push(pc)
      },
    })
    assert('retry: the next tick persists the customer', persisted.length === 1)
    assert('retry: and reports it as newly added', added.length === 1)
    assert('retry: only then is the durable copy removed', node.live(inbox).length === 0)
    assert('retry: the registry holds the customer', registrar.registry.has(alice.paymentCode()))
  }

  // --- Test-double fidelity: Remove must not expire the survivors ----------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    await rpc.add('d', 'A', 'long')
    await rpc.add('d', 'B', 'long')
    await rpc.add('d', 'C', 'long')
    await rpc.remove('d', 'A')
    assert('node: removing one entry leaves the others live', node.live('d').join(',') === 'B,C')
    await rpc.remove('d', 'never-added')
    assert('node: removing an absent entry changes nothing', node.live('d').join(',') === 'B,C')
    node.advance(MODE_TTL_MS.long + 1)
    assert('node: survivors still expire on schedule', node.live('d').length === 0)
  }

  // --- Multi-entry drain, including a malformed entry -----------------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const registrar = new Registrar(bob, new Registry())
    const inbox = inboxName(bob.paymentCode())

    for (const seed of [ALICE_SEED, CAROL_SEED]) {
      await registerWithReceiver(rpc, PaynymIdentity.fromSeed(seed), bob.paymentCode())
    }
    await rpc.add(inbox, 'garbage-not-a-sealed-envelope', 'long')

    const added = await registrar.poll(rpc)
    assert('drain: both valid registrations accepted', added.length === 2)
    assert('drain: malformed entry counted as rejected', registrar.rejected() === 1)
    assert('drain: inbox fully emptied', node.live(inbox).length === 0)
  }

  // --- Testnet registration and derivation, end to end ---------------------
  // Address derivation threads the network and once threw 'Version mismatch',
  // so a testnet receiver accepted customers happily and then died at the first
  // watch-window build — a late failure, at the point of use.
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED, TESTNET)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED, TESTNET)
    const registrar = new Registrar(bob, new Registry())

    await registerWithReceiver(rpc, alice, bob.paymentCode())
    const added = await registrar.poll(rpc)
    assert('testnet: registration accepted end to end', added.length === 1 && added[0] === alice.paymentCode())
    assert('testnet: nothing rejected', registrar.rejected() === 0)

    const window = watchWindow(bob, registrar.registry)
    assert('testnet: watch window is non-empty', window.length > 0)
    assert(
      'testnet: every watch address encodes as testnet',
      window.every((w) => w.address[0] === 'm' || w.address[0] === 'n'),
    )
    assert(
      'testnet: customer agrees on every watch address',
      window.every((w) => alice.sendAddress(bob.paymentCode(), w.index) === w.address),
    )
  }
})()

console.log('')
if (failures === 0) {
  console.log('PASS — durability, substitution resistance, test-double fidelity, testnet.')
} else {
  console.log(`FAIL — ${failures} regression check(s) failed.`)
  process.exit(1)
}
