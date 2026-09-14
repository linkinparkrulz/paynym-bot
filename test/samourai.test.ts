// Samourai wire-format compatibility.
//
// The pinned vector below was produced by COMPILING AND RUNNING Samourai's own
// Java (extlibj Z85.java and ECDHKeySet.java verbatim, plus a harness
// reproducing CryptoUtil.encrypt and EncryptedMessage.serialize). Agreeing with
// their implementation is the entire point here — a test that only checked our
// code against itself would prove nothing about whether a real wallet can talk
// to us.
//
// Their CryptoUtil.encryptAES_CTR calls cipher.init(DECRYPT_MODE, ...) inside
// the encrypt path. That is harmless for CTR, where both directions are the
// same keystream XOR, and the harness reproduced it as-is rather than
// "correcting" it, so this vector matches what real clients actually emit.

import { PaynymIdentity } from '../src/identity.ts'
import { networkFor } from '../src/state.ts'
import { Registrar, Registry, registerWithReceiver, samouraiInboxName, inboxName } from '../src/register.ts'
import { SorobanRPC } from '../src/soroban.ts'
import { memoryNode } from './memory-node.ts'
import {
  keySetFromMaster,
  openSamourai,
  parseSamouraiEnvelope,
  samouraiDecrypt,
  samouraiEncrypt,
  sealSamourai,
  z85Decode,
  z85Encode,
} from '../src/samourai.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const h = (x: string) => Uint8Array.from(Buffer.from(x, 'hex'))
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex')

// --- pinned against their compiled Java -------------------------------------
const MASTER = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90'
const IV = '000102030405060708090a0b0c0d0e0f'
const MSG = '{"v":2,"type":"paynym.register","hello":"world"}'
const JAVA_Z85 =
  '009c61o!#m2NH?C3>iWSd3[m@@JrLC@d1DJ<?O%Uh0C9NJOCmGAuY[QVT%$yaVUfzEBa7t!lGfa+]>-YT3t%Nglgd9:Um8So?*dxU5<p6=(f0>)a>bdXW]%=LcE)h+kV?Ck}.2c>NrWxgKHAL]y2[=9sXl<=#=J+'

const keys = keySetFromMaster(h(MASTER))
assert('KDF encryptionKey matches Java',
  hex(keys.encryptionKey) === '717c3e482bc5ef463e0096b38cb5d7521714826aad0d6f39ccfb9f39f827edfe')
assert('KDF hmacKey matches Java',
  hex(keys.hmacKey) === '2b3faa54eaa716e5f43dd4ae6fcefbd33c968184c20e4c8c6d4bd0277dda50ee')
assert('full ciphertext matches Java byte for byte',
  z85Encode(samouraiEncrypt(MSG, keys, h(IV))) === JAVA_Z85)
assert('we can read what their implementation produced',
  samouraiDecrypt(z85Decode(JAVA_Z85), keys) === MSG)

// --- Z85 --------------------------------------------------------------------
assert('Z85 round-trips a whole-block input', hex(z85Decode(z85Encode(h('deadbeef')))) === 'deadbeef')
for (let n = 1; n <= 9; n++) {
  // Partial final blocks are where their padding differs from the ZeroMQ spec.
  const bytes = h('ab'.repeat(n))
  assert(`Z85 round-trips ${n} byte(s)`, hex(z85Decode(z85Encode(bytes))).startsWith(hex(bytes)))
}
assert('Z85 output uses only the Z85 alphabet', /^[0-9A-Za-z.\-:+=^!/*?&<>()[\]{}@%$#]+$/.test(JAVA_Z85))

// --- authenticated encryption ----------------------------------------------
const sealed = samouraiEncrypt('hello', keys)
assert('round-trips through our own code', samouraiDecrypt(sealed, keys) === 'hello')

// CTR is malleable, so the MAC must be checked BEFORE decrypting.
const flipped = Uint8Array.from(sealed)
flipped[flipped.length - 1] ^= 0x01
assert('a tampered ciphertext is rejected', samouraiDecrypt(flipped, keys) === null)
const badMac = Uint8Array.from(sealed)
badMac[20] ^= 0x01
assert('a tampered HMAC is rejected', samouraiDecrypt(badMac, keys) === null)
assert('a truncated payload is rejected', samouraiDecrypt(sealed.subarray(0, 40), keys) === null)
assert('the wrong key does not open it',
  samouraiDecrypt(sealed, keySetFromMaster(h('00'.repeat(32)))) === null)

// --- envelope ---------------------------------------------------------------
assert('parses a well-formed envelope',
  parseSamouraiEnvelope('{"sender":"PM8T","payload":"abc"}')?.sender === 'PM8T')
assert('rejects a non-JSON entry', parseSamouraiEnvelope('not-json') === null)
assert('rejects a missing sender', parseSamouraiEnvelope('{"payload":"abc"}') === null)
assert('rejects an empty payload', parseSamouraiEnvelope('{"sender":"PM8T","payload":""}') === null)

// --- end to end through the Registrar --------------------------------------
const NET = networkFor('testnet')
const merchant = PaynymIdentity.fromSeed(h('a1'.repeat(32)), NET)
const alice = PaynymIdentity.fromSeed(h('b2'.repeat(32)), NET)
const mallory = PaynymIdentity.fromSeed(h('c3'.repeat(32)), NET)

assert('the stock-wallet directory is the bare payment code hash',
  samouraiInboxName(merchant.paymentCode()) !== inboxName(merchant.paymentCode()))

const registrar = new Registrar(merchant, new Registry())
const entry = sealSamourai(
  alice.identityPrivateKey(),
  alice.paymentCode(),
  merchant.paymentCode(),
  'any cahoots payload at all',
)
assert('a stock-wallet entry registers the customer', registrar.ingest(entry) === alice.paymentCode())

// The security property that lets the Samourai path skip an inner signature:
// forging a payload for someone else's payment code needs THEIR private key.
const forged = sealSamourai(
  mallory.identityPrivateKey(),
  alice.paymentCode(), // lying about who this is from
  merchant.paymentCode(),
  'let me in as alice',
)
assert('a forged sender is rejected', registrar.ingest(forged) === null)

// --- both formats drain from their own directories --------------------------
await (async () => {
  const node = memoryNode()
  const rpc = new SorobanRPC(node.transport)
  const r = new Registrar(merchant, new Registry())

  await registerWithReceiver(rpc, alice, merchant.paymentCode()) // our format
  await rpc.add(
    samouraiInboxName(merchant.paymentCode()),
    sealSamourai(mallory.identityPrivateKey(), mallory.paymentCode(), merchant.paymentCode(), 'hi'),
    'long',
  )
  await rpc.add(samouraiInboxName(merchant.paymentCode()), '{"sender":"PM8Tbogus","payload":"zz"}', 'long')

  const added = await r.poll(rpc)
  assert('both wire formats register', added.length === 2)
  assert('our sender registered', r.registry.has(alice.paymentCode()))
  assert('the stock-wallet sender registered', r.registry.has(mallory.paymentCode()))
  assert('the bogus entry was rejected', r.rejected() === 1)
  assert('our inbox drained', node.live(inboxName(merchant.paymentCode())).length === 0)
  assert('the stock-wallet inbox drained', node.live(samouraiInboxName(merchant.paymentCode())).length === 0)
})()

console.log('')
if (failures === 0) {
  console.log('PASS — byte-compatible with Samourai, verified against their compiled Java.')
} else {
  console.log(`FAIL — ${failures} compatibility check(s) failed.`)
  process.exit(1)
}
