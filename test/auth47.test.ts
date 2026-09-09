// Auth47 offline test: challenge construction, signature verification, and
// the security properties the storefront relies on (relay binding, single-use
// nonces, expiry). No network; a proof is built here exactly as Ashigaru would
// build one (recoverable Bitcoin signed-message over the prepared challenge).
// Run: node --experimental-strip-types --no-warnings test/auth47.test.ts

import { PaynymIdentity } from '../src/identity.ts'
import { networkFor } from '../src/state.ts'
import { p2pkhAddress, nodeFromPaymentCode } from '../src/bip47.ts'
import {
  Auth47Sessions,
  challengeURI,
  signedForm,
  signedMessageBytes,
  verifyProof,
  verifySignedMessage,
  sameResource,
  newNonce,
  NONCE_TTL_MS,
} from '../src/auth47.ts'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'

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
const bob = PaynymIdentity.fromSeed(BOB_SEED, network) // the merchant/bot

// --- challenge construction ---------------------------------------------------

const origin = 'http://shopexampleonion7charactersonion.onion'
const callback = `${origin}/api/auth47/callback`
const nonce = newNonce()
const expires = Math.floor(Date.now() / 1000) + 300
const fullUri = challengeURI(nonce, expires, callback, origin)

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

// --- proof construction, as a conforming wallet builds it ----------------------

function signLikeAWallet(identity: PaynymIdentity, message: string): string {
  const digest = sha256(sha256(signedMessageBytes(message)))
  const sig = secp256k1.sign(digest, identity.identityPrivateKey())
  const compact = sig.toBytes()
  const out = new Uint8Array(65)
  out.set(compact)
  out[64] = sig.recovery + 31 // bitcoinjs-message header: 31..34 = compressed key
  return Buffer.from(out).toString('base64')
}

const proof = {
  auth47_response: '1.0',
  challenge: prepared,
  signature: signLikeAWallet(alice, prepared),
  nym: alice.paymentCode(),
}

const v = verifyProof(proof, network)
assert('a conforming proof verifies', v.ok)
assert('verified proof yields the payment code', v.ok && v.paymentCode === alice.paymentCode())

// The signature must check against the nym's NOTIFICATION address.
const notificationAddress = p2pkhAddress(
  nodeFromPaymentCode(alice.paymentCode()).deriveChild(0).publicKey!,
  network,
)
assert('notification address derived from the code is the verify target', (() => {
  return verifySignedMessage(prepared, notificationAddress, proof.signature, network)
})())

// --- rejections ---------------------------------------------------------------

assert('wrong version rejected', !verifyProof({ ...proof, auth47_response: '2.0' }, network).ok)
assert('malformed payload rejected', !verifyProof('nope', network).ok)
assert('challenge still carrying c rejected', !verifyProof({
  ...proof,
  challenge: fullUri,
}, network).ok)
assert('expired challenge rejected', (() => {
  const past = challengeURI(newNonce(), Math.floor(Date.now() / 1000) - 10, callback, origin)
  return !verifyProof({
    auth47_response: '1.0',
    challenge: signedForm(past)!,
    signature: signLikeAWallet(alice, signedForm(past)!),
    nym: alice.paymentCode(),
  }, network).ok
})())
assert('forged signature rejected', !verifyProof({ ...proof, signature: signLikeAWallet(bob, prepared) }, network).ok)
assert('address-only proof rejected (cannot identify a counterparty)', (() => {
  const withAddress = { ...proof } as Record<string, unknown>
  delete withAddress.nym
  withAddress.address = notificationAddress
  return !verifyProof(withAddress, network).ok
})())
assert('garbage nym rejected', !verifyProof({ ...proof, nym: 'not-a-payment-code' }, network).ok)
assert('proof for a different challenge rejected', (() => {
  const other = signedForm(challengeURI(newNonce(), expires, callback, origin))!
  return !verifyProof({ ...proof, challenge: other }, network).ok
})())

// A payment code is network-agnostic: the notification key it names is the
// same on every network, and verifyProof derives the expected address under
// whichever network it is handed, so a valid proof verifies under both. This
// is inherent to Auth47 (a code carries no network), and is fine here: the
// proof establishes CONTROL of the code; which chain the customer is paid on
// is fixed by the storefront's own network, and the address it serves is
// derived on that network.
assert('proof verifies under either network (the code is network-agnostic)', (() => {
  const vTest = verifyProof(proof, networkFor('testnet'))
  return vTest.ok && vTest.paymentCode === alice.paymentCode()
})())

// --- signed-message framing ----------------------------------------------------

// The framing must be exactly bitcoinjs-message's: magic + varint + message.
{
  const msg = 'auth47://abc?e=1&r=http://x'
  const bytes = signedMessageBytes(msg)
  const expected = Buffer.concat([
    // 0x18 control byte, then the literal, then varint length, then message.
    Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8'),
    Buffer.from([Buffer.byteLength(msg)]),
    Buffer.from(msg, 'utf8'),
  ])
  assert('signed-message framing matches bitcoinjs-message', Buffer.from(bytes).equals(expected))
}

// --- resource binding ------------------------------------------------------------

assert('same resource, different trailing slash, matches', sameResource(`${origin}/`, origin))
assert('different origin does not match', !sameResource('http://evil.onion', origin))

// --- nonce / session store -------------------------------------------------------

const sessions = new Auth47Sessions()
const n1 = newNonce()
sessions.issue(n1)
assert('issued nonce can be taken once', sessions.take(n1) !== null)
assert('nonce is single-use', sessions.take(n1) === null)

const n2 = newNonce()
assert('unknown nonce is rejected', sessions.take(n2) === null)

const n3 = newNonce()
sessions.issue(n3)
const rec = sessions.take(n3)!
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
clockSessions.issue(n4)
fakeNow += NONCE_TTL_MS + 1
assert('nonce expires with its TTL', clockSessions.take(n4) === null)

const sid5 = clockSessions.mint(alice.paymentCode())
fakeNow += 12 * 60 * 60 * 1000 + 1
assert('session expires with its TTL', clockSessions.session(sid5) === null)

console.log('')
if (failures === 0) {
  console.log('PASS — auth47 challenges build, proofs verify, and attacks fail closed.')
} else {
  console.log(`FAIL — ${failures} auth47 check(s) failed.`)
  process.exit(1)
}
