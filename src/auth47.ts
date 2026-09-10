// Auth47: authenticate a customer with their BIP47 payment code, then hand
// them a receive address over the storefront — the flow the storefront was
// missing. A stock BIP47 wallet (Samourai/Ashigaru) scans a challenge QR, signs
// it with the payment code's notification key, and POSTs the proof back; we
// verify it and mint a session that can be shown an address.
//
// Grounded in the Auth47 specification (Dojo-Open-Source-Project/
// auth47-specification) and shaped on Dojo Bay's deployment of it, which is the
// implementation Ashigaru and Samourai wallets demonstrably interoperate with:
//
//   - The challenge is `auth47://<nonce>?c=<callback>&e=<unix>&r=<resource>`,
//     fully percent-decoded, with r and e ALWAYS explicit rather than relying
//     on the spec's implicit `r = c` rule.
//   - The wallet signs the challenge WITHOUT the c parameter (spec's challenge
//     preparation: inject r, strip c).
//   - The signature is a base64 Bitcoin signed message (recoverable), and it
//     is verified against the NOTIFICATION ADDRESS derived from the submitted
//     payment code — not by recovering a public key — which is exactly the
//     shape @dojo-tools/auth47 and Dojo Bay use.
//   - The resource `r` must name this storefront (relay binding): a proof
//     minted for another site must not authenticate here, even though its
//     signature is valid.
//
// Dojo Bay hard-codes mainnet in its Auth47 path; we thread the network from
// the state file so a testnet deployment verifies against testnet addresses.

import { randomBytes } from 'node:crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { nodeFromPaymentCode, p2pkhAddress } from './bip47.ts'
import type { Network } from './bip47.ts'

export const AUTH47_RESPONSE_VERSION = '1.0'

/** Challenges are single-use and die quickly; the wallet round-trip is short. */
export const NONCE_TTL_MS = 5 * 60 * 1000
/** A minted session is good for the rest of a shopping visit, not longer. */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000

/**
 * Ceiling on live challenges. `issue()` is unauthenticated — anyone with the
 * onion address can POST for one — and gc() only reclaims entries that have
 * actually expired, so without a cap a few minutes of POSTs pin unbounded
 * memory. The limit is far above any real storefront's concurrent shoppers and
 * far below anything that matters to the process.
 */
export const MAX_LIVE_NONCES = 4096

/**
 * Bitcoin signed-message prefix, exactly as bitcoinjs-message defines it:
 * a literal 0x18 control byte, then "Bitcoin Signed Message:\n". The 0x18 is
 * load-bearing — omit it and the digest differs, pubkey recovery lands on a
 * different key, and every real wallet signature fails as "bad signature".
 */
const MESSAGE_MAGIC = '\x18Bitcoin Signed Message:\n'

function textEncoder(): TextEncoder {
  return new TextEncoder()
}

/**
 * The exact bytes a wallet signs for a message: magic, varint length, message.
 * Matches bitcoinjs-message's format for messages under 253 bytes (an auth47
 * challenge always is).
 */
export function signedMessageBytes(message: string): Uint8Array {
  const msg = textEncoder().encode(message)
  if (msg.length >= 253) throw new Error('message too long for varint length prefix')
  const magic = textEncoder().encode(MESSAGE_MAGIC)
  const out = new Uint8Array(magic.length + 1 + msg.length)
  out.set(magic)
  out[magic.length] = msg.length
  out.set(msg, magic.length + 1)
  return out
}

/** Double-SHA256 digest over the signed-message framing. */
function messageDigest(message: string): Uint8Array {
  return sha256(sha256(signedMessageBytes(message)))
}

/**
 * Verify a base64 recoverable Bitcoin signed-message signature against the
 * P2PKH address it claims to come from. Recovery rather than pubkey-verify is
 * required: the wallet hands us a 65-byte [r | s | header] compact signature
 * and no public key.
 *
 * The header byte encodes the recovery id and key length as bitcoinjs-message
 * and every wallet produces them: `27 + recid` for an uncompressed public key
 * (27..30), `27 + recid + 4` for a compressed one (31..34, which is what
 * Ashigaru and Samourai emit, since BIP47 keys are compressed). The recovery
 * bit masked out is still the low two bits either way.
 */
export function verifySignedMessage(
  message: string,
  address: string,
  signatureBase64: string,
  network: Network,
): boolean {
  let compact: Uint8Array
  try {
    const raw = Buffer.from(signatureBase64, 'base64')
    // 65 bytes is the only shape this format has: 32 r + 32 s + 1 header.
    // Anything else is not a recoverable signature in it.
    if (raw.length !== 65) return false
    compact = Uint8Array.from(raw)
  } catch {
    return false
  }
  const header = compact[64]
  if (header < 27 || header > 34) return false
  try {
    const digest = messageDigest(message)
    const sig = secp256k1.Signature.fromCompact(compact.subarray(0, 64))
    const recovery = (header - 27) & 3
    const compressed = header >= 31
    const pub = sig.addRecoveryBit(recovery as 0 | 1 | 2 | 3).recoverPublicKey(digest)
    // The address hashes whichever key length the header declared: compressed
    // keys hash their 33 bytes, uncompressed theirs 65.
    return p2pkhAddress(pub.toRawBytes(compressed), network) === address
  } catch {
    return false
  }
}

// --- Challenge construction -------------------------------------------------

/**
 * Build the URI shown to the wallet (QR / link). `callbackUrl` lands in `c`,
 * and `resource` in `r` — both explicit, always, per Dojo Bay: the implicit
 * `r = c` rule of the spec relies on wallet behaviour we need not trust.
 *
 * The URI is emitted fully percent-decoded (URL.toString() would escape ':'
 * and '&'), because that is the byte sequence wallets expect to sign.
 */
export function challengeURI(
  nonce: string,
  expiresUnix: number,
  callbackUrl: string,
  resource: string,
): string {
  const params = [
    `c=${callbackUrl}`,
    `e=${expiresUnix}`,
    `r=${resource}`,
  ]
  return `auth47://${nonce}?${params.join('&')}`
}

/**
 * The challenge preparation of the spec, reproduced: this is the string the
 * wallet signs — the URI with the c parameter stripped (r is already present).
 * Used by tests to build proofs and by verify to cross-check what was signed.
 */
export function signedForm(uri: string): string | null {
  try {
    const u = new URL(uri)
    u.searchParams.delete('c')
    return decodeURIComponent(u.toString())
  } catch {
    return null
  }
}

/** Nonces are the "host" of the auth47 URI: alphanumeric. */
export function newNonce(): string {
  return randomBytes(16).toString('hex')
}

// --- Proof validation --------------------------------------------------------

export type Auth47Proof = {
  auth47_response: string
  challenge: string
  signature: string
  nym?: string
  address?: string
}

export type VerifyError =
  | 'malformed'
  | 'bad version'
  | 'bad challenge'
  | 'bad payment code'
  | 'bad signature'
  | 'expired'

export type VerifyResult =
  | { ok: true; paymentCode: string }
  | { ok: false; error: VerifyError }

/**
 * Validate a proof in full, except for nonce/relay concerns the caller owns
 * (the nonce store and the r-binding are per-deployment state, this function
 * is pure). Checks:
 *
 *   - payload shape and auth47_response === "1.0"
 *   - the challenge is a well-formed auth47 URI whose query carries r and
 *     does NOT carry c (a wallet signs the prepared form; a proof whose
 *     challenge still has c was not produced by a conforming wallet)
 *   - expiry: e, if present, is in the future
 *   - the nym decodes as a BIP47 payment code (address-only proofs are
 *     rejected: an address cannot identify a counterparty for BIP47)
 *   - the signature recovers to the notification address of that nym
 */
export function verifyProof(
  proof: unknown,
  network: Network,
  now = Date.now(),
): VerifyResult {
  if (proof === null || typeof proof !== 'object') return { ok: false, error: 'malformed' }
  const p = proof as Partial<Auth47Proof>

  if (p.auth47_response !== AUTH47_RESPONSE_VERSION) return { ok: false, error: 'bad version' }
  if (typeof p.challenge !== 'string' || typeof p.signature !== 'string') {
    return { ok: false, error: 'malformed' }
  }
  if (typeof p.nym !== 'string') {
    // An address proof is spec-valid but cannot name a BIP47 counterparty.
    return { ok: false, error: 'bad payment code' }
  }

  let challenge: URL
  try {
    if (!p.challenge.startsWith('auth47:')) throw new Error()
    challenge = new URL(p.challenge)
  } catch {
    return { ok: false, error: 'bad challenge' }
  }
  if (challenge.protocol !== 'auth47:') return { ok: false, error: 'bad challenge' }
  if (!/^[a-zA-Z0-9]+$/.test(challenge.hostname)) return { ok: false, error: 'bad challenge' }
  if (challenge.hash) return { ok: false, error: 'bad challenge' }
  if (challenge.searchParams.get('c') !== null) return { ok: false, error: 'bad challenge' }
  const r = challenge.searchParams.get('r')
  if (!r) return { ok: false, error: 'bad challenge' }
  const e = challenge.searchParams.get('e')
  if (e !== null) {
    const when = Number(e)
    if (!Number.isInteger(when) || when * 1000 <= now) return { ok: false, error: 'expired' }
  }

  // The nym must decode; nodeFromPaymentCode throws on any malformed code.
  let notificationAddress: string
  try {
    const node = nodeFromPaymentCode(p.nym)
    notificationAddress = p2pkhAddress(node.deriveChild(0).publicKey!, network)
  } catch {
    return { ok: false, error: 'bad payment code' }
  }

  if (!verifySignedMessage(p.challenge, notificationAddress, p.signature, network)) {
    return { ok: false, error: 'bad signature' }
  }
  return { ok: true, paymentCode: p.nym }
}

/** Compare two http(s) resources as Dojo Bay does: origin-normalised. */
export function sameResource(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin
  } catch {
    return a === b
  }
}

// --- Nonce and session stores ------------------------------------------------

type NonceRecord = { expires: number; used: boolean; sessionId?: string }

/**
 * In-memory challenge and session state. Single-process by design: this bot is
 * one receiver in one process, and persisting auth sessions across restarts
 * would outlive the storefront's promise that a session is a live visit.
 * Nonces are pruned on access, so an abandoned challenge cannot pin memory.
 */
export class Auth47Sessions {
  private nonces = new Map<string, NonceRecord>()
  private sessions = new Map<string, { paymentCode: string; expires: number }>()
  private now: () => number

  constructor(now: () => number = Date.now) {
    this.now = now
  }

  private gc(): void {
    const now = this.now()
    for (const [k, v] of this.nonces) if (v.expires < now) this.nonces.delete(k)
    for (const [k, v] of this.sessions) if (v.expires < now) this.sessions.delete(k)
  }

  /**
   * Record a freshly issued challenge nonce. Returns false when the store is
   * already at MAX_LIVE_NONCES, so the caller can refuse rather than grow: the
   * endpoint that calls this is unauthenticated.
   */
  issue(nonce: string, ttlMs = NONCE_TTL_MS): boolean {
    this.gc()
    if (this.nonces.size >= MAX_LIVE_NONCES) return false
    this.nonces.set(nonce, { expires: this.now() + ttlMs, used: false })
    return true
  }

  /**
   * Is this nonce live and unconsumed? A Map lookup, so it is the cheap gate
   * to put in front of signature verification — which costs an ECDSA recovery
   * and a base58 encode on input nobody has authenticated yet.
   *
   * Deliberately does NOT consume: a wallet that submits a malformed proof
   * should not burn the customer's challenge.
   */
  peek(nonce: string): boolean {
    const rec = this.nonces.get(nonce)
    return rec !== undefined && !rec.used && rec.expires >= this.now()
  }

  /**
   * Consume a nonce: single-use, exactly once. Returns the record so the
   * caller can bind a session to it, or null when unknown/expired/used.
   *
   * A record that has already been used is left in place, NOT deleted. It
   * carries the session id the customer's browser is still polling for, so
   * dropping it here would let a replayed (or merely retried) proof destroy
   * the legitimate customer's session before they ever claimed it. It expires
   * on its own shortly afterwards.
   */
  take(nonce: string): NonceRecord | null {
    const rec = this.nonces.get(nonce)
    if (!rec) return null
    if (rec.expires < this.now()) {
      this.nonces.delete(nonce)
      return null
    }
    if (rec.used) return null
    rec.used = true
    rec.expires = this.now() + NONCE_TTL_MS // short window for the poll claim
    return rec
  }

  /** Attach a session id to a consumed nonce for the browser poll to claim. */
  claim(nonce: string, sessionId: string): void {
    const rec = this.nonces.get(nonce)
    if (rec) rec.sessionId = sessionId
  }

  /**
   * The session a nonce minted, handed out ONCE. The nonce is the payload of
   * the QR on the customer's screen, so anyone who photographs it could
   * otherwise poll for the session id the moment the customer authenticates.
   * Claiming it retires the nonce, so only the first poll — the customer's own
   * browser — gets the session.
   */
  claimed(nonce: string): string | null {
    const rec = this.nonces.get(nonce)
    if (!rec || !rec.used || !rec.sessionId) return null
    this.nonces.delete(nonce)
    return rec.sessionId
  }

  /** Mint a session for an authenticated payment code. Returns its id. */
  mint(paymentCode: string, ttlMs = SESSION_TTL_MS): string {
    this.gc()
    const id = randomBytes(24).toString('hex')
    this.sessions.set(id, { paymentCode, expires: this.now() + ttlMs })
    return id
  }

  /** The authenticated payment code for a session id, or null. */
  session(sessionId: string): { paymentCode: string } | null {
    const s = this.sessions.get(sessionId)
    if (!s || s.expires < this.now()) {
      this.sessions.delete(sessionId)
      return null
    }
    return { paymentCode: s.paymentCode }
  }

  /** End a session early (customer done, or wants out). */
  drop(sessionId: string): void {
    this.sessions.delete(sessionId)
  }
}
