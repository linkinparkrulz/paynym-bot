// Storefront behaviour, and above all what it does NOT expose.
//
// This server sits behind the onion and is readable by anyone with the
// address. The payment code and network are meant to be public. The registered
// customer payment codes are not: that set is the merchant's counterparty
// graph, and even its SIZE is their trading volume. These tests pin that
// boundary so a later change cannot quietly widen it.
//
// The Auth47 session flow is the one deliberate exception: a customer who
// proves control of their payment code may learn the address their code
// derives. The proof is the gate — without one, nothing customer-shaped is
// served.

import { PaynymIdentity } from '../src/identity.ts'
import { createStorefront } from '../src/server.ts'
import { Registry } from '../src/register.ts'
import { networkFor } from '../src/state.ts'
import { signedForm, challengeURI, signedMessageBytes } from '../src/auth47.ts'
import type { AddressInfo } from 'node:net'
import type { NetworkName } from '../src/state.ts'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const seed = Uint8Array.from(Buffer.from('33'.repeat(64), 'hex'))
const customerSeed = Uint8Array.from(Buffer.from('44'.repeat(64), 'hex'))
const networkName: NetworkName = 'testnet'
const identity = PaynymIdentity.fromSeed(seed, networkFor(networkName))
const customer = PaynymIdentity.fromSeed(customerSeed, networkFor(networkName))

const registry = new Registry()
let persisted = 0
const server = createStorefront({
  identity,
  network: networkName,
  label: 'Test Shop',
  registry,
  persist: async () => {
    persisted++
  },
})
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
const { port } = server.address() as AddressInfo
const base = `http://127.0.0.1:${port}`

// --- public status ----------------------------------------------------------
const statusRes = await fetch(`${base}/api/status`)
const status = await statusRes.json()
assert('status responds 200', statusRes.status === 200)
assert('status exposes the payment code', status.paymentCode === identity.paymentCode())
assert('status exposes the network', status.network === 'testnet')
assert('status exposes the label', status.label === 'Test Shop')
assert('status is not cached', statusRes.headers.get('cache-control') === 'no-store')
assert('status advertises the auth47 flow', status.auth47 === true)

// --- the privacy boundary ---------------------------------------------------
// Serialise the whole response and assert nothing customer-shaped is in it.
const raw = JSON.stringify(status)
assert('status does not leak a customer payment code', !raw.includes(customer.paymentCode()))
assert('status has no senders field', !('senders' in status))
assert('status has no watch list', !('watch' in status) && !('addresses' in status))
assert(
  'status discloses no customer count under any key',
  !Object.keys(status).some((k) => /sender|customer|count|registered|watch/i.test(k)),
)

// --- the page ---------------------------------------------------------------
const pageRes = await fetch(`${base}/`)
const page = await pageRes.text()
assert('page responds 200', pageRes.status === 200)
assert('page is html', (pageRes.headers.get('content-type') ?? '').startsWith('text/html'))
assert('page sets a content security policy', pageRes.headers.get('content-security-policy') !== null)
assert('page sends no referrer', pageRes.headers.get('referrer-policy') === 'no-referrer')
// Onion-only: the page must not pull anything from the clearnet.
assert('page loads no external resources', !/https?:\/\/(?!127\.0\.0\.1)/i.test(page))
assert('page does not inline the payment code', !page.includes(identity.paymentCode()))
assert('page ships the vendored QR script', (await fetch(`${base}/js/qrcode.js`)).status === 200)

// --- auth47 flow, end to end as wallet + browser ------------------------------
const challengeRes = await fetch(`${base}/api/auth47/challenge`, { method: 'POST' })
const challenge = await challengeRes.json()
assert('challenge responds 200', challengeRes.status === 200)
assert('challenge carries a URI and expiry', typeof challenge.uri === 'string' && typeof challenge.expires === 'number')
assert(
  'challenge callback points at this server',
  new URL(challenge.uri).searchParams.get('c') === `${base}/api/auth47/callback`,
)

// Wallet side: sign the prepared form with the notification key, base64 compact+recovery.
function walletSignature(message: string): string {
  const digest = sha256(sha256(signedMessageBytes(message)))
  const sig = secp256k1.sign(digest, customer.identityPrivateKey())
  const out = new Uint8Array(65)
  out.set(sig.toBytes())
  out[64] = sig.recovery + 31 // bitcoinjs-message header: 31..34 = compressed key
  return Buffer.from(out).toString('base64')
}

const prepared = signedForm(challenge.uri)!
const proof = {
  auth47_response: '1.0',
  challenge: prepared,
  signature: walletSignature(prepared),
  nym: customer.paymentCode(),
}

// Before the proof: the poll is pending and no session exists.
const earlyPoll = await fetch(`${base}/api/auth47/poll?nonce=${challenge.nonce}`)
assert('poll is pending before the wallet answers', earlyPoll.status === 202)

const callbackRes = await fetch(`${base}/api/auth47/callback`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(proof),
})
assert('callback accepts a valid proof', callbackRes.status === 200)

// Registration happened and was persisted before the session was minted.
assert('callback registered the customer', registry.has(customer.paymentCode()))
assert('callback persisted the registry first', persisted > 0)

const pollRes = await fetch(`${base}/api/auth47/poll?nonce=${challenge.nonce}`)
const poll = await pollRes.json()
assert('poll resolves to a session after the proof', pollRes.status === 200 && poll.status === 'authenticated')
assert('poll yields a session id', typeof poll.sessionId === 'string')

const sessionRes = await fetch(`${base}/api/session/${poll.sessionId}`)
const session = await sessionRes.json()
assert('session endpoint responds 200', sessionRes.status === 200)
assert(
  'session address is the BIP47 receive address at the current index',
  session.address === identity.receiveAddress(customer.paymentCode(), 0),
)
assert('session carries the index', session.index === 0)
assert('session does not carry a spend key', !('spendKey' in session) && !/priv/i.test(JSON.stringify(session)))

// --- hostile cases -----------------------------------------------------------
const replay = await fetch(`${base}/api/auth47/callback`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(proof), // same proof, replayed
})
assert('nonce replay is rejected', replay.status === 401)

// A proof signed for a different resource (relay attack) must not authenticate.
const evilOrigin = 'http://evilshop.onion'
const evilUri = challengeURI(challenge.nonce, Math.floor(challenge.expires / 1000), `${evilOrigin}/api/auth47/callback`, evilOrigin)
const evilPrepared = signedForm(evilUri)!
const evilRes = await fetch(`${base}/api/auth47/callback`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    auth47_response: '1.0',
    challenge: evilPrepared,
    signature: walletSignature(evilPrepared),
    nym: customer.paymentCode(),
  }),
})
assert('proof bound to another site is rejected', evilRes.status === 401)

// A session id that does not exist serves nothing.
const bogusSession = await fetch(`${base}/api/session/deadbeef`)
assert('unknown session id 404s', bogusSession.status === 404)

// A customer-shaped query on the public endpoint leaks nothing: sessions are
// unguessable, but the registry must never be enumerable via the status API.
const statusRes2 = await fetch(`${base}/api/status`)
const raw2 = JSON.stringify(await statusRes2.json())
assert('status still leaks nothing after a registration', !raw2.includes(customer.paymentCode()))

// --- auth47 disabled (plain storefront) -------------------------------------
const bare = createStorefront({ identity, network: networkName })
await new Promise<void>((resolve) => bare.listen(0, '127.0.0.1', resolve))
const barePort = (bare.address() as AddressInfo).port
const bareChallenge = await fetch(`http://127.0.0.1:${barePort}/api/auth47/challenge`, { method: 'POST' })
assert('bare storefront refuses auth47 challenges', bareChallenge.status === 503)
const bareStatus = await (await fetch(`http://127.0.0.1:${barePort}/api/status`)).json()
assert('bare storefront does not advertise auth47', bareStatus.auth47 === false)
await new Promise<void>((resolve) => bare.close(() => resolve()))

// --- everything else --------------------------------------------------------
assert('health check responds', (await fetch(`${base}/healthz`)).status === 200)
assert('unknown paths 404', (await fetch(`${base}/../secrets`)).status === 404)
assert(
  'page writes are rejected',
  (await fetch(`${base}/`, { method: 'POST' })).status === 405,
)

await new Promise<void>((resolve) => server.close(() => resolve()))

console.log('')
if (failures === 0) {
  console.log('PASS — storefront serves the PayNym, gates sessions behind auth47, and leaks nothing else.')
} else {
  console.log(`FAIL — ${failures} storefront check(s) failed.`)
  process.exit(1)
}
