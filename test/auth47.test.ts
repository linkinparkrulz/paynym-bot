// Auth47, verified against the Samourai libraries themselves.
//
// This suite exists in the shape it does because of one bug. The verification
// here used to be hand-rolled, and it read the recovery flag off the WRONG END
// of the signature: bitcoinjs-message emits `[header | r | s]`, and the code
// read `[r | s | header]`. Every real wallet proof failed as "bad signature",
// and this suite passed the whole time — because its own helper signed with the
// same wrong layout it verified.
//
// So the rule now is: the wallet-facing bytes are produced by
// @dojo-tools/bitcoinjs-message, never by a local reimplementation. A helper
// that builds proofs the way this file wants them to look proves nothing.
// Run: node --experimental-strip-types --no-warnings test/auth47.test.ts

import { PaynymIdentity } from '../src/identity.ts'
import { networkFor } from '../src/state.ts'
import {
  Auth47Sessions,
  challengeURI,
  libNetwork,
  newNonce,
  notificationAddresses,
  notificationAddressOf,
  sameResource,
  signedForm,
  verifyProof,
  MAX_LIVE_NONCES,
  NONCE_TTL_MS,
} from '../src/auth47.ts'
import { bitcoinMessageFactory } from '@dojo-tools/bitcoinjs-message'
import * as bip47utils from '@dojo-tools/bip47/utils'
import ecc from '@bitcoinerlab/secp256k1'

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

const network = networkFor('mainnet')
const alice = PaynymIdentity.fromSeed(ALICE_SEED, network) // the customer/wallet
const bob = PaynymIdentity.fromSeed(BOB_SEED, network) // another wallet entirely

const message = bitcoinMessageFactory(ecc)
const MAINNET = bip47utils.networks.bitcoin

/**
 * Sign exactly as a wallet does: through the library, which owns the framing
 * AND the signature layout. Nothing in this file constructs those bytes itself
 * — that is the mistake this suite is here to make impossible.
 */
function walletSign(identity: PaynymIdentity, challenge: string): string {
  const sig = message.sign(challenge, identity.identityPrivateKey(), true, MAINNET.messagePrefix)
  return Buffer.from(sig).toString('base64')
}

const origin = 'http://shopexampleonion7charactersonion.onion'
const callback = `${origin}/api/auth47/callback`
const nonce = newNonce()
const expires = Math.floor(Date.now() / 1000) + 300
const fullUri = challengeURI(nonce, expires, callback, origin)

// --- challenge construction ---------------------------------------------------

assert('challenge URI carries c, e, and explicit r', (() => {
  const u = new URL(fullUri)
  return u.protocol === 'auth47:' &&
    u.hostname === nonce &&
    u.searchParams.get('c') === callback &&
    u.searchParams.get('r') === origin &&
    u.searchParams.get('e') === String(expires)
})())

const prepared = signedForm(fullUri)!
assert('signed form strips c and keeps r, e', (() => {
  const u = new URL(prepared)
  return u.searchParams.get('c') === null &&
    u.searchParams.get('r') === origin &&
    u.searchParams.get('e') === String(expires)
})())
assert('signed form nonce is intact', new URL(prepared).hostname === nonce)

// --- the signature layout, pinned ---------------------------------------------
//
// The regression that started all this. A wallet signature is
// [header | r | s]: the recovery flag is the FIRST byte, 27..34 for a P2PKH
// key (27+recid uncompressed, 31+recid compressed). Reading it off the last
// byte parses r's leading byte as the flag, which is why every genuine proof
// was refused.
{
  const raw = Buffer.from(walletSign(alice, prepared), 'base64')
  assert('a wallet signature is 65 bytes', raw.length === 65)
  assert(
    'the recovery flag is the FIRST byte, in 27..34',
    raw[0]! >= 27 && raw[0]! <= 34,
  )
  assert(
    'and the LAST byte is signature material, not a flag',
    !(raw[64]! >= 27 && raw[64]! <= 34) || raw[0]! !== raw[64]!,
  )
}

// --- a real proof verifies ------------------------------------------------------

const proof = {
  auth47_response: '1.0',
  challenge: prepared,
  signature: walletSign(alice, prepared),
  nym: alice.paymentCode(),
}

const v = verifyProof(proof, callback)
assert('a wallet-shaped proof verifies', v.ok)
assert('verified proof yields the payment code', v.ok && v.paymentCode === alice.paymentCode())

// The address the signature recovers to is the payment code's notification
// address, which is what binds the proof to the nym.
assert('the notification address is what was signed from', (() => {
  const addr = notificationAddressOf(alice.paymentCode(), 'bitcoin')
  return message.verify(prepared, addr, proof.signature, MAINNET.messagePrefix)
})())

// --- rejections ---------------------------------------------------------------

assert('a proof signed by another wallet is rejected',
  !verifyProof({ ...proof, signature: walletSign(bob, prepared) }, callback).ok)
assert('a tampered challenge is rejected',
  !verifyProof({ ...proof, challenge: prepared.replace(/r=[^&]*/, 'r=http://evil.onion') }, callback).ok)
assert('malformed payload rejected', !verifyProof('nope', callback).ok)
assert('wrong version rejected', !verifyProof({ ...proof, auth47_response: '2.0' }, callback).ok)
assert('challenge still carrying c rejected', !verifyProof({ ...proof, challenge: fullUri }, callback).ok)
assert('garbage nym rejected', !verifyProof({ ...proof, nym: 'not-a-payment-code' }, callback).ok)
assert('address-only proof rejected (cannot identify a counterparty)', (() => {
  const withAddress = { ...proof } as Record<string, unknown>
  delete withAddress.nym
  withAddress.address = notificationAddressOf(alice.paymentCode(), 'bitcoin')
  return !verifyProof(withAddress, callback).ok
})())
assert('an expired challenge is rejected', (() => {
  // Built by hand: the library's generateURI refuses to mint a past expiry at
  // all, which is itself the right behaviour — but the verifier still has to
  // refuse one that arrives from outside.
  const past = `auth47://${newNonce()}?e=${Math.floor(Date.now() / 1000) - 10}&r=${origin}`
  return !verifyProof({
    auth47_response: '1.0',
    challenge: past,
    signature: walletSign(alice, past),
    nym: alice.paymentCode(),
  }, callback).ok
})())
assert('and generateURI refuses to mint one in the past', (() => {
  try {
    challengeURI(newNonce(), Math.floor(Date.now() / 1000) - 10, callback, origin)
    return false
  } catch {
    return true
  }
})())

// --- both notification-address derivations are accepted -------------------------
//
// A PayNym is a mainnet identity, but a wallet in testnet mode signs from the
// testnet derivation of the same code. Refusing that silently rejects good
// proofs; Dojo Bay accepts either, and so do we. Both come from the same code.
{
  const addrs = notificationAddresses(alice.paymentCode())
  assert('a payment code yields two derivations', addrs.length === 2)
  assert('they differ', addrs[0] !== addrs[1])
  assert('mainnet form is a 1-address', addrs[0]!.startsWith('1'))
  assert('testnet form is an m/n-address', /^[mn]/.test(addrs[1]!))
  assert('libNetwork maps our names onto the library\'s',
    libNetwork('mainnet') === 'bitcoin' && libNetwork('testnet') === 'testnet')
}

// --- resource binding ------------------------------------------------------------

assert('same resource, different trailing slash, matches', sameResource(`${origin}/`, origin))
assert('host case is not a different site', sameResource(origin.toUpperCase().replace('HTTP', 'http'), origin))
assert('different origin does not match', !sameResource('http://evil.onion', origin))
assert('a different path IS a different resource', !sameResource(`${origin}/other`, origin))
assert('unparseable is equal to nothing', !sameResource('not a url', origin))

// --- nonce / session store -------------------------------------------------------

const forNonce = (n: string) => challengeURI(n, expires, callback, origin)

const sessions = new Auth47Sessions()
const n1 = newNonce()
sessions.issue(n1, forNonce(n1))
assert('issued nonce can be taken once', sessions.take(n1) !== null)
assert('nonce is single-use', sessions.take(n1) === null)

const n2 = newNonce()
assert('unknown nonce is rejected', sessions.take(n2) === null)

const n3 = newNonce()
sessions.issue(n3, forNonce(n3))
sessions.take(n3)
const sid = sessions.mint(alice.paymentCode())
sessions.claim(n3, sid)
assert('claimed nonce yields the session id', sessions.claimed(n3) === sid)
assert('unclaimed nonce yields nothing', sessions.claimed(n1) === null)

const session = sessions.session(sid)
assert('session resolves to the payment code', session?.paymentCode === alice.paymentCode())
sessions.drop(sid)
assert('dropped session is gone', sessions.session(sid) === null)

// Expiry, via an injected clock.
let fakeNow = Date.now()
const clockSessions = new Auth47Sessions(() => fakeNow)
const n4 = newNonce()
clockSessions.issue(n4, forNonce(n4))
fakeNow += NONCE_TTL_MS + 1
assert('nonce expires with its TTL', clockSessions.take(n4) === null)

const sid5 = clockSessions.mint(alice.paymentCode())
fakeNow += 12 * 60 * 60 * 1000 + 1
assert('session expires with its TTL', clockSessions.session(sid5) === null)

// The store cannot be grown without bound: issue() is unauthenticated.
{
  const bounded = new Auth47Sessions()
  let issued = 0
  for (let i = 0; i < MAX_LIVE_NONCES + 50; i++) {
    const n = newNonce()
    if (bounded.issue(n, forNonce(n))) issued++
  }
  assert('issue stops at the cap', issued === MAX_LIVE_NONCES)
  const overflow = newNonce()
  assert('and says so, rather than growing quietly',
    bounded.issue(overflow, forNonce(overflow)) === false)
}

// peek is the cheap gate in front of signature verification, and must not
// consume: a malformed proof should not burn the customer's challenge.
{
  const gate = new Auth47Sessions()
  const n = newNonce()
  gate.issue(n, forNonce(n))
  assert('peek sees a live nonce', gate.peek(n))
  assert('peek does not consume it', gate.peek(n) && gate.take(n) !== null)
  assert('peek is false once consumed', !gate.peek(n))
  assert('peek is false for an unknown nonce', !gate.peek(newNonce()))
}

// A replayed proof must not destroy the real customer's pending session.
{
  const st = new Auth47Sessions()
  const n = newNonce()
  st.issue(n, forNonce(n))
  st.take(n)
  const sessionId = st.mint(alice.paymentCode())
  st.claim(n, sessionId)
  assert('a replay is still refused', st.take(n) === null)
  assert('but the pending session survives the replay', st.claimed(n) === sessionId)
}

// The session is claimed once: the nonce is the QR on the customer's screen.
{
  const once = new Auth47Sessions()
  const n = newNonce()
  once.issue(n, forNonce(n))
  once.take(n)
  const sessionId = once.mint(alice.paymentCode())
  once.claim(n, sessionId)
  assert('the first claim wins', once.claimed(n) === sessionId)
  assert('a second claim gets nothing', once.claimed(n) === null)
}

console.log('')
if (failures === 0) {
  console.log('PASS — auth47 verified through the Samourai libraries, signature layout pinned.')
} else {
  console.log(`FAIL — ${failures} auth47 check(s) failed.`)
  process.exit(1)
}
