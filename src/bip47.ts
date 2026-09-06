// BIP47 "reusable payment codes" derivation core.
//
// This module is deliberately transport-agnostic: nothing here references a
// txid, an outpoint, or any on-chain data. A BIP47 payment address is a pure
// function of the two parties' payment codes, which is exactly why the
// notification transaction can be replaced by any authenticated channel (see
// ../README.md and ./register.ts).
//
// Verified against the official BIP47 test vectors (Alice & Bob) in
// ../test/vectors.test.ts. The one subtle point the vectors pin down: the
// SENDER uses the private key at account child index 0 (m/47'/0'/0'/0, i.e. the
// notification key), NOT the account node key. The receiver varies its own
// child index i against the sender's fixed child-0 public key.

import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { ripemd160 } from '@noble/hashes/ripemd160'
import { HDKey } from '@scure/bip32'
import { base58check as base58checkFactory } from '@scure/base'

const base58check = base58checkFactory(sha256)
const Point = secp256k1.ProjectivePoint
const CURVE_N = secp256k1.CURVE.n

export type Network = {
  // P2PKH version byte: 0x00 mainnet, 0x6f testnet.
  p2pkhVersion: number
  // SLIP-44 coin type for the m/47'/coin'/account' path (0 mainnet, 1 testnet).
  coinType: number
}

export const MAINNET: Network = { p2pkhVersion: 0x00, coinType: 0 }
export const TESTNET: Network = { p2pkhVersion: 0x6f, coinType: 1 }

const PAYMENT_CODE_VERSION = 0x01
const PAYMENT_CODE_PREFIX = 0x47 // makes the base58 string start with "PM8T..."

function toHex(u8: Uint8Array): string {
  return Buffer.from(u8).toString('hex')
}
function fromHex(h: string): Uint8Array {
  return Uint8Array.from(Buffer.from(h, 'hex'))
}
function scalarTo32(n: bigint): Uint8Array {
  return fromHex(n.toString(16).padStart(64, '0'))
}

/** HASH160 = RIPEMD160(SHA256(x)). */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data))
}

/** Encode a compressed pubkey as a base58check P2PKH address. */
export function p2pkhAddress(pubkey: Uint8Array, network: Network = MAINNET): string {
  const h = hash160(pubkey)
  const payload = new Uint8Array(1 + h.length)
  payload[0] = network.p2pkhVersion
  payload.set(h, 1)
  return base58check.encode(payload)
}

export type PaymentCodeParts = { pubkey: Uint8Array; chainCode: Uint8Array }

/** Encode an account (pubkey + chain code) as a v1 payment code string. */
export function encodePaymentCode(pubkey: Uint8Array, chainCode: Uint8Array): string {
  if (pubkey.length !== 33) throw new Error('payment code pubkey must be 33 bytes (compressed)')
  if (chainCode.length !== 32) throw new Error('payment code chain code must be 32 bytes')
  const body = new Uint8Array(80)
  body[0] = PAYMENT_CODE_VERSION
  body[1] = 0x00 // features bitfield: no bitmessage, no notification-over-chain flags set
  body.set(pubkey, 2) // bytes 2..34  : sign byte + 32-byte x
  body.set(chainCode, 35) // bytes 35..66 : chain code
  // bytes 67..79 reserved, left zero
  const payload = new Uint8Array(1 + 80)
  payload[0] = PAYMENT_CODE_PREFIX
  payload.set(body, 1)
  return base58check.encode(payload)
}

/** Decode a v1 payment code string into its account pubkey and chain code. */
export function decodePaymentCode(paymentCode: string): PaymentCodeParts {
  const payload = base58check.decode(paymentCode)
  if (payload[0] !== PAYMENT_CODE_PREFIX) throw new Error('invalid payment code prefix')
  const body = payload.subarray(1)
  if (body.length !== 80) throw new Error('invalid payment code length')
  if (body[0] !== PAYMENT_CODE_VERSION) throw new Error('unsupported payment code version')
  return { pubkey: body.slice(2, 35), chainCode: body.slice(35, 67) }
}

// Version bytes for the synthetic extended key below. This is an internal
// detail of the CKDpub vehicle, NOT a network parameter: the synthetic xpub
// never leaves this function, is never serialised, and CKDpub yields identical
// child pubkeys whatever version is stamped on it. Threading a network in here
// only created the chance to stamp a version @scure/bip32 then rejects, which
// is what made every testnet derivation throw 'Version mismatch'.
const VEHICLE_XPUB_VERSION = 0x0488b21e

/**
 * Build a watch-only HD node from a payment code so we can CKDpub into its
 * account children (B_i / A_i). We reuse @scure/bip32's audited CKDpub by
 * synthesising the xpub the account pubkey+chaincode represent.
 *
 * Network-independent by construction: a payment code carries no network
 * information, and the network only matters when encoding a final address
 * (see p2pkhAddress).
 */
export function nodeFromPaymentCode(paymentCode: string): HDKey {
  const { pubkey, chainCode } = decodePaymentCode(paymentCode)
  const data = new Uint8Array(78)
  const dv = new DataView(data.buffer)
  dv.setUint32(0, VEHICLE_XPUB_VERSION)
  data[4] = 3 // depth of m/47'/coin'/account'
  // parent fingerprint (5..9) and child number (9..13) intentionally zero
  data.set(chainCode, 13)
  data.set(pubkey, 45)
  return HDKey.fromExtendedKey(base58check.encode(data))
}

/**
 * Compute the BIP47 scalar tweak s from an ECDH shared point.
 * s = SHA256(S.x) where S.x is the 32-byte big-endian x-coordinate.
 * Throws if s is not a valid scalar (0 < s < n); callers skip that index.
 */
function sharedSecretScalar(shared: InstanceType<typeof Point>): bigint {
  const x = scalarTo32(shared.toAffine().x)
  const s = BigInt('0x' + toHex(sha256(x)))
  if (s <= 0n || s >= CURVE_N) throw new Error('shared secret out of curve order; skip this index')
  return s
}

/**
 * RECEIVER side. Given our own account node and the SENDER's payment code,
 * derive the P2PKH address at which we will receive their i-th payment.
 *
 *   S_i = b_i * A_0     (b_i = our child-i privkey, A_0 = sender child-0 pubkey)
 *   s_i = SHA256(S_i.x)
 *   addr = P2PKH(B_i + s_i*G)
 */
export function receiveAddress(
  ourAccount: HDKey,
  senderPaymentCode: string,
  index: number,
  network: Network = MAINNET,
): string {
  const senderNode = nodeFromPaymentCode(senderPaymentCode)
  const A0 = Point.fromHex(senderNode.deriveChild(0).publicKey!)
  const ourChild = ourAccount.deriveChild(index)
  const bI = BigInt('0x' + toHex(ourChild.privateKey!))
  const BI = Point.fromHex(ourChild.publicKey!)
  const s = sharedSecretScalar(A0.multiply(bI))
  const pub = BI.add(Point.BASE.multiply(s))
  return p2pkhAddress(pub.toRawBytes(true), network)
}

/**
 * RECEIVER side. Private scalar (hex) that spends `receiveAddress` at `index`.
 *   b'_i = (b_i + s_i) mod n
 */
export function receivePrivateKey(
  ourAccount: HDKey,
  senderPaymentCode: string,
  index: number,
  network: Network = MAINNET,
): string {
  const senderNode = nodeFromPaymentCode(senderPaymentCode)
  const A0 = Point.fromHex(senderNode.deriveChild(0).publicKey!)
  const ourChild = ourAccount.deriveChild(index)
  const bI = BigInt('0x' + toHex(ourChild.privateKey!))
  const BI = Point.fromHex(ourChild.publicKey!)
  const s = sharedSecretScalar(A0.multiply(bI))
  const spend = (bI + s) % CURVE_N
  return spend.toString(16).padStart(64, '0')
}

/**
 * SENDER side. Given our own account node and the RECEIVER's payment code,
 * derive the P2PKH address to pay for our i-th payment to them. This must equal
 * the receiver's `receiveAddress(...i)` — that equality is the entire mechanism.
 *
 *   S_i = a_0 * B_i     (a_0 = our child-0 privkey, B_i = receiver child-i pubkey)
 *   addr = P2PKH(B_i + SHA256(S_i.x)*G)
 */
export function sendAddress(
  ourAccount: HDKey,
  receiverPaymentCode: string,
  index: number,
  network: Network = MAINNET,
): string {
  const receiverNode = nodeFromPaymentCode(receiverPaymentCode)
  const a0 = BigInt('0x' + toHex(ourAccount.deriveChild(0).privateKey!))
  const BI = Point.fromHex(receiverNode.deriveChild(index).publicKey!)
  const s = sharedSecretScalar(BI.multiply(a0))
  const pub = BI.add(Point.BASE.multiply(s))
  return p2pkhAddress(pub.toRawBytes(true), network)
}
