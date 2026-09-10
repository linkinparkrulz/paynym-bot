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
import { connect as netConnect, createServer as createNetServer } from 'node:net'
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

/**
 * Reserve a free port before building the storefront.
 *
 * The auth47 flow is bound to the host the operator published, and that host
 * has to be known when the storefront is constructed — so the test cannot
 * listen on port 0 and learn it afterwards. Opening a listener, reading its
 * port and closing it is enough: nothing else on the box is racing for
 * ephemeral ports during a test run.
 */
async function freePort(): Promise<number> {
  const probe = createNetServer()
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve))
  const { port } = probe.address() as AddressInfo
  await new Promise<void>((resolve) => probe.close(() => resolve()))
  return port
}

/**
 * A raw HTTP/1.0 request, so the Host header can be set to something other
 * than the address actually dialled — which is the whole point of the
 * relay-binding tests below. fetch() derives Host from the URL and ignores an
 * override, so it cannot express this. HTTP/1.0 keeps the response unchunked
 * and therefore trivial to slice apart.
 */
function rawRequest(
  port: number,
  method: string,
  path: string,
  host: string,
  body?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = netConnect(port, '127.0.0.1', () => {
      const payload = body ?? ''
      socket.write(
        `${method} ${path} HTTP/1.0\r\nHost: ${host}\r\n` +
          `Content-Type: application/json\r\n` +
          `Content-Length: ${Buffer.byteLength(payload)}\r\n\r\n${payload}`,
      )
    })
    let out = ''
    socket.setEncoding('utf8')
    socket.on('data', (chunk) => {
      out += chunk
    })
    socket.on('end', () => {
      resolve({
        status: Number(out.split('\r\n')[0]?.split(' ')[1] ?? 0),
        body: out.slice(out.indexOf('\r\n\r\n') + 4),
      })
    })
    socket.on('error', reject)
  })
}

const registry = new Registry()
let persisted = 0
const port = await freePort()
// The published host: what an operator records in state.json, and what the
// test dials, so ordinary fetch() sends a matching Host header.
const publishedHost = `127.0.0.1:${port}`
const server = createStorefront({
  identity,
  network: networkName,
  label: 'Test Shop',
  registry,
  persist: async () => {
    persisted++
  },
  onionHost: publishedHost,
})
await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve))
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

// A proof signed for a different resource (relay attack) must not
// authenticate. This needs a LIVE nonce to be a real test of the r binding:
// against a spent one the nonce gate rejects first and the binding is never
// reached, which is what made the original version of this check vacuous.
const freshForRelay = await (await fetch(`${base}/api/auth47/challenge`, { method: 'POST' })).json()
const evilOrigin = 'http://evilshop.onion'
const evilUri = challengeURI(
  freshForRelay.nonce,
  Math.floor(freshForRelay.expires / 1000),
  `${evilOrigin}/api/auth47/callback`,
  evilOrigin,
)
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
assert(
  'and rejected FOR the binding, not for a spent nonce',
  (await evilRes.json()).error === 'proof was signed for a different site',
)

// --- the relay attack the Host header used to enable --------------------------
//
// Reproduces the real thing end to end. The attacker asks THIS server for a
// challenge while claiming a different Host. If the server takes the resource
// from the request, the challenge it mints names the attacker's site in both
// c and r, so the victim's wallet signs a proof the attacker can relay
// straight back here — and the r comparison passes, because both halves are
// the attacker's own string.
const ATTACKER_HOST = 'evilphishsite.onion'

const spoofedChallenge = await rawRequest(port, 'POST', '/api/auth47/challenge', ATTACKER_HOST)
assert(
  'a challenge addressed to another host is refused',
  spoofedChallenge.status === 421,
)

// And the whole relay, driven with a challenge minted for the real host: the
// attacker cannot substitute their own Host at the callback either.
const realChallenge = await (await fetch(`${base}/api/auth47/challenge`, { method: 'POST' })).json()
const realPrepared = signedForm(realChallenge.uri)!
const relayed = await rawRequest(
  port,
  'POST',
  '/api/auth47/callback',
  ATTACKER_HOST,
  JSON.stringify({
    auth47_response: '1.0',
    challenge: realPrepared,
    signature: walletSignature(realPrepared),
    nym: customer.paymentCode(),
  }),
)
assert('a proof relayed under another Host is refused', relayed.status === 421)
assert(
  'the spoofed relay minted no session',
  (await (await fetch(`${base}/api/auth47/poll?nonce=${realChallenge.nonce}`)).json()).status ===
    'pending',
)

// The legitimate host still works through the same raw path, so the check
// above is testing the Host and not merely the transport.
const legitRaw = await rawRequest(port, 'POST', '/api/auth47/challenge', publishedHost)
assert('the published host is still accepted', legitRaw.status === 200)

// --- the session claim is handed out once ------------------------------------
// The nonce is the payload of the QR on the customer's screen. Whoever polls
// first gets the session; a second poll must not hand the same session to an
// onlooker who photographed it.
const onceChallenge = await (await fetch(`${base}/api/auth47/challenge`, { method: 'POST' })).json()
const oncePrepared = signedForm(onceChallenge.uri)!
await fetch(`${base}/api/auth47/callback`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    auth47_response: '1.0',
    challenge: oncePrepared,
    signature: walletSignature(oncePrepared),
    nym: customer.paymentCode(),
  }),
})
const firstPoll = await fetch(`${base}/api/auth47/poll?nonce=${onceChallenge.nonce}`)
assert('the first poll claims the session', firstPoll.status === 200)
const secondPoll = await fetch(`${base}/api/auth47/poll?nonce=${onceChallenge.nonce}`)
assert('a second poll gets nothing', secondPoll.status === 202)

// The poll is a read; it must not accept writes.
assert(
  'poll rejects a POST',
  (await fetch(`${base}/api/auth47/poll?nonce=x`, { method: 'POST' })).status === 405,
)

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

// --- fail closed with no published host -------------------------------------
// A registry alone is not enough. Without a host the operator configured,
// there is nothing to bind a proof to, and a binding taken from the request is
// no binding at all — so the flow is not served, rather than served weakly.
const unbound = createStorefront({
  identity,
  network: networkName,
  registry: new Registry(),
  persist: async () => {},
})
await new Promise<void>((resolve) => unbound.listen(0, '127.0.0.1', resolve))
const unboundPort = (unbound.address() as AddressInfo).port
const unboundBase = `http://127.0.0.1:${unboundPort}`
assert(
  'no published host means no auth47 challenges',
  (await fetch(`${unboundBase}/api/auth47/challenge`, { method: 'POST' })).status === 503,
)
assert(
  'no published host means no auth47 callbacks',
  (await fetch(`${unboundBase}/api/auth47/callback`, { method: 'POST', body: '{}' })).status === 503,
)
assert(
  'and the page is told the flow is off',
  (await (await fetch(`${unboundBase}/api/status`)).json()).auth47 === false,
)
assert(
  'the payment code is still served, so the shop still works',
  (await (await fetch(`${unboundBase}/api/status`)).json()).paymentCode === identity.paymentCode(),
)
await new Promise<void>((resolve) => unbound.close(() => resolve()))

// --- a failed persist must not leave a memory-only registration -------------
// Same rule as the daemon's inbox drain: the in-memory registry and the state
// file must not disagree. If persistence fails, the add is rolled back so the
// customer can retry, rather than the watcher watching addresses that vanish
// on restart.
{
  const flaky = new Registry()
  const flakyPort = await freePort()
  let failNext = true
  const flakyServer = createStorefront({
    identity,
    network: networkName,
    registry: flaky,
    persist: async () => {
      if (failNext) {
        failNext = false
        throw new Error('disk full')
      }
    },
    onionHost: `127.0.0.1:${flakyPort}`,
  })
  await new Promise<void>((resolve) => flakyServer.listen(flakyPort, '127.0.0.1', resolve))
  const flakyBase = `http://127.0.0.1:${flakyPort}`

  const c1 = await (await fetch(`${flakyBase}/api/auth47/challenge`, { method: 'POST' })).json()
  const p1 = signedForm(c1.uri)!
  const failed = await fetch(`${flakyBase}/api/auth47/callback`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      auth47_response: '1.0',
      challenge: p1,
      signature: walletSignature(p1),
      nym: customer.paymentCode(),
    }),
  })
  assert('a failed persist fails the callback', failed.status === 500)
  assert('and leaves nothing behind in memory', !flaky.has(customer.paymentCode()))

  // The retry succeeds, which is the point of rolling back.
  const c2 = await (await fetch(`${flakyBase}/api/auth47/challenge`, { method: 'POST' })).json()
  const p2 = signedForm(c2.uri)!
  const retried = await fetch(`${flakyBase}/api/auth47/callback`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      auth47_response: '1.0',
      challenge: p2,
      signature: walletSignature(p2),
      nym: customer.paymentCode(),
    }),
  })
  assert('the retry registers the customer', retried.status === 200)
  assert('and the registry now holds them', flaky.has(customer.paymentCode()))
  await new Promise<void>((resolve) => flakyServer.close(() => resolve()))
}

// --- the watch list is bounded ----------------------------------------------
// Registration is open by design, and generating payment codes is free, so an
// unbounded watch list is an unauthenticated write. Past the cap a NEW customer
// is refused; one already registered is always still served, because money may
// already sit at an address we are watching for them.
{
  const capped = new Registry(1) // capacity of one, so the cap is reachable
  const cappedPort = await freePort()
  const cappedServer = createStorefront({
    identity,
    network: networkName,
    registry: capped,
    persist: async () => {},
    onionHost: `127.0.0.1:${cappedPort}`,
  })
  await new Promise<void>((resolve) => cappedServer.listen(cappedPort, '127.0.0.1', resolve))
  const cappedBase = `http://127.0.0.1:${cappedPort}`

  const authenticate = async (who: PaynymIdentity): Promise<number> => {
    const c = await (await fetch(`${cappedBase}/api/auth47/challenge`, { method: 'POST' })).json()
    const prep = signedForm(c.uri)!
    const digest = sha256(sha256(signedMessageBytes(prep)))
    const sig = secp256k1.sign(digest, who.identityPrivateKey())
    const out = new Uint8Array(65)
    out.set(sig.toBytes())
    out[64] = sig.recovery + 31
    const res = await fetch(`${cappedBase}/api/auth47/callback`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        auth47_response: '1.0',
        challenge: prep,
        signature: Buffer.from(out).toString('base64'),
        nym: who.paymentCode(),
      }),
    })
    return res.status
  }

  const second = PaynymIdentity.fromSeed(
    Uint8Array.from(Buffer.from('55'.repeat(64), 'hex')),
    networkFor(networkName),
  )
  assert('the first customer is accepted', (await authenticate(customer)) === 200)
  assert('a new customer past the cap is refused', (await authenticate(second)) === 503)
  assert('the cap held', capped.size() === 1)
  assert('the refused customer was not registered', !capped.has(second.paymentCode()))
  assert(
    'an already-registered customer is still served',
    (await authenticate(customer)) === 200,
  )
  await new Promise<void>((resolve) => cappedServer.close(() => resolve()))
}

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
