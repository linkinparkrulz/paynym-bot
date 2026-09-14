// Offline end-to-end test of the notification-less registration protocol.
// Customer -> Soroban -> merchant, with no network. Run: npm run protocol

import { PaynymIdentity } from '../src/identity.ts'
import { SorobanRPC } from '../src/soroban.ts'
import type { RpcTransport } from '../src/soroban.ts'
import { sealToPaymentCode } from '../src/channel.ts'
import {
  Registrar,
  Registry,
  registerWithReceiver,
  buildRegisterEnvelope,
} from '../src/register.ts'
import { watchWindow } from '../src/watcher.ts'

// --- In-memory Soroban node -------------------------------------------------
function memoryNode(): RpcTransport {
  const dirs = new Map<string, string[]>()
  return async (payload: any) => {
    const { method, params } = payload
    const a = params[0]
    if (method === 'directory.Add') {
      const list = dirs.get(a.Name) ?? []
      if (!list.includes(a.Entry)) list.push(a.Entry)
      dirs.set(a.Name, list)
      return { result: { Status: 'success' } }
    }
    if (method === 'directory.List') {
      return { result: { Name: a.Name, Entries: dirs.get(a.Name) ?? [] } }
    }
    if (method === 'directory.Remove') {
      dirs.set(a.Name, (dirs.get(a.Name) ?? []).filter((e) => e !== a.Entry))
      return { result: { Status: 'success' } }
    }
    return { result: null }
  }
}

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'))

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const ALICE_SEED = fromHex(
  '64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a',
)
const BOB_SEED = fromHex(
  '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110',
)
const CAROL_SEED = fromHex('05'.repeat(64))

const rpc = new SorobanRPC(memoryNode())

// Bob is the always-online merchant; Alice is a customer.
const bob = PaynymIdentity.fromSeed(BOB_SEED)
const alice = PaynymIdentity.fromSeed(ALICE_SEED)
const carol = PaynymIdentity.fromSeed(CAROL_SEED)

const registrar = new Registrar(bob, new Registry())

await (async () => {
  assert('registry empty before registration', registrar.registry.all().length === 0)

  // The customer needs nothing but the payment code from the merchant's page —
  // no rendezvous fetch, no published key, no notification transaction.
  const posted = await registerWithReceiver(rpc, alice, bob.paymentCode())
  assert('customer posted registration', posted)

  const added = await registrar.poll(rpc)
  assert('merchant registered exactly one customer', added.length === 1)
  assert('registered code is alice', added[0] === alice.paymentCode())

  // The payoff: merchant's watch address == customer's pay address, from
  // payment codes alone. This is what makes the payment work with no notif tx.
  const window = watchWindow(bob, registrar.registry)
  let allMatch = window.length > 0
  for (const w of window) {
    if (alice.sendAddress(bob.paymentCode(), w.index) !== w.address) allMatch = false
  }
  assert('watch addresses == customer pay addresses', allMatch)

  const again = await registrar.poll(rpc)
  assert('re-poll registers nothing new', again.length === 0)

  // A forged envelope: valid JSON, signature over a DIFFERENT payment code.
  const forged = buildRegisterEnvelope(alice, bob.paymentCode())
  forged.paymentCode = carol.paymentCode() // claim Carol's code, keep Alice's signature
  assert(
    'forged registration rejected',
    registrar.ingest(sealToPaymentCode(bob.paymentCode(), JSON.stringify(forged))) === null,
  )

  // v2 receiver binding: an envelope Alice addressed to Carol must not register
  // her with Bob. Under v1 this replayed verbatim into any merchant's inbox.
  const forCarol = buildRegisterEnvelope(alice, carol.paymentCode())
  assert(
    'envelope addressed to another merchant is rejected',
    registrar.ingest(sealToPaymentCode(bob.paymentCode(), JSON.stringify(forCarol))) === null,
  )

  // ...and the same envelope IS accepted by the merchant it was addressed to.
  const carolRegistrar = new Registrar(carol, new Registry())
  assert(
    'the addressed merchant accepts it',
    carolRegistrar.ingest(sealToPaymentCode(carol.paymentCode(), JSON.stringify(forCarol))) ===
      alice.paymentCode(),
  )
})()

console.log('')
if (failures === 0) {
  console.log('PASS — notification-less registration works end-to-end.')
} else {
  console.log(`FAIL — ${failures} protocol check(s) failed.`)
  process.exit(1)
}
