// Auth47: authenticate a customer with their BIP47 payment code, then hand
// them a receive address over the storefront. A stock BIP47 wallet
// (Samourai/Ashigaru) scans a challenge QR, signs it with the payment code's
// notification key, and POSTs the proof back; we verify it and mint a session
// that can be shown an address.
//
// The verification is NOT implemented here. It is delegated to the Samourai
// libraries — @dojo-tools/auth47, @dojo-tools/bip47, @dojo-tools/bitcoinjs-message
// — which is what The Dojo Bay does (see its server/crypto.ts, "thin wrappers
// over the audited Samourai libraries"), and they are the implementations
// Ashigaru and Samourai demonstrably interoperate with.
//
// That delegation is the whole point, and it was learned the hard way. This
// file previously hand-rolled the signed-message framing and the signature
// decode, and got the signature layout backwards: bitcoinjs-message emits
// `[header | r | s]`, with the recovery flag as the FIRST byte, and this code
// read it as `[r | s | header]`. Every real wallet proof failed as "bad
// signature". The test suite passed throughout, because its helper signed with
// the same wrong layout it verified — self-consistent, and wrong.
//
// So: no bespoke crypto on this path. If something here disagrees with a
// wallet, the fix belongs in the library, not in a local reimplementation of it.

import { randomBytes } from 'node:crypto'
import { Auth47Verifier } from '@dojo-tools/auth47'
import { BIP47Factory } from '@dojo-tools/bip47'
import * as bip47utils from '@dojo-tools/bip47/utils'
import ecc from '@bitcoinerlab/secp256k1'
import type { NetworkName } from './state.ts'

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

const bip47 = BIP47Factory(ecc)

/**
 * The networks a proof is checked against.
 *
 * Both, always, and the reason is Dojo Bay's: a PayNym is a mainnet identity,
 * but a wallet running in testnet mode derives the notification address for
 * THAT network, so the same payment code signs from a different address
 * depending on which mode the customer's wallet happens to be in. Insisting on
 * one derivation silently refuses perfectly good proofs. Accepting either is no
 * weaker — both addresses come from the same payment code, and it is that code
 * the proof binds to.
 */
const VERIFY_NETWORKS = ['bitcoin', 'testnet'] as const

// --- Challenge construction -------------------------------------------------

/** Build the URI shown to the wallet (QR / link), via the library's builder. */
export function challengeURI(
  nonce: string,
  expiresUnix: number,
  callbackUrl: string,
  resource: string,
): string {
  return new Auth47Verifier(ecc, callbackUrl).generateURI({
    nonce,
    expires: expiresUnix,
    resource,
  })
}

/**
 * The challenge preparation of the spec: the URI with the c parameter stripped
 * (r is already present). This is the string the wallet signs and echoes back.
 * Identical to Dojo Bay's signedForm.
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

/** The address a payment code's challenge signature must recover to. */
export function notificationAddressOf(
  paymentCode: string,
  network: 'bitcoin' | 'testnet' = 'bitcoin',
): string {
  return bip47.fromBase58(paymentCode, bip47utils.networks[network]).getNotificationAddress()
}

/**
 * Every address a payment code could legitimately have signed from. See
 * VERIFY_NETWORKS. Lifted from Dojo Bay's notificationAddresses.
 */
export function notificationAddresses(paymentCode: string): string[] {
  const out: string[] = []
  for (const net of VERIFY_NETWORKS) {
    try {
      const a = notificationAddressOf(paymentCode, net)
      if (!out.includes(a)) out.push(a)
    } catch {
      /* skip a network this code cannot be decoded for */
    }
  }
  return out
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

export type VerifyResult =
  | { ok: true; paymentCode: string }
  | { ok: false; error: string }

/**
 * Validate a proof, except for the nonce and relay concerns the caller owns
 * (both are per-deployment state; this function is pure).
 *
 * The signature check is the library's, run against both notification-address
 * derivations. Everything this adds on top is a policy decision the library
 * cannot make for us: that an address-only proof cannot name a BIP47
 * counterparty, and that the callback parameter must already be stripped.
 */
export function verifyProof(proof: unknown, callbackUrl: string): VerifyResult {
  if (proof === null || typeof proof !== 'object') return { ok: false, error: 'malformed' }
  const p = proof as Partial<Auth47Proof>

  if (typeof p.nym !== 'string' || p.nym.length === 0) {
    // Spec-valid, but an address cannot identify a BIP47 counterparty: there is
    // no payment code to derive a receive address from.
    return { ok: false, error: 'proof does not carry a payment code' }
  }

  const verifier = new Auth47Verifier(ecc, callbackUrl)
  let lastError = 'invalid signature'
  for (const network of VERIFY_NETWORKS) {
    const res = verifier.verifyProof(proof as Auth47Proof, network)
    if (res.result === 'ok') return { ok: true, paymentCode: p.nym }
    lastError = res.error
  }
  return { ok: false, error: lastError }
}

/**
 * Two URLs naming the same resource, compared as parsed URLs so a trailing
 * slash or a difference in host case is not a different site, while a different
 * origin or path is. Anything that does not parse equals nothing. Dojo Bay's
 * comparison, which is stricter than matching origins alone.
 */
export function sameResource(a: string, b: string): boolean {
  try {
    const norm = (u: string) => {
      const x = new URL(u)
      return x.origin.toLowerCase() + x.pathname.replace(/\/+$/, '') + x.search
    }
    return norm(a) === norm(b)
  } catch {
    return false
  }
}

/** Map our stored network name onto the library's. */
export function libNetwork(name: NetworkName): 'bitcoin' | 'testnet' {
  return name === 'mainnet' ? 'bitcoin' : 'testnet'
}

// --- Nonce and session stores ------------------------------------------------

type NonceRecord = {
  expires: number
  used: boolean
  sessionId?: string
  /**
   * The challenge URI we minted for this nonce.
   *
   * Kept so a rejected proof can be compared against what we actually issued,
   * rather than only against what the wallet echoed back. It does not change
   * what is accepted — `verifyProof` still checks the posted string — but it
   * is the difference between "bad signature" and "the wallet signed the
   * percent-encoded form of our challenge and posted the decoded one".
   */
  uri: string
}

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
  issue(nonce: string, uri: string, ttlMs = NONCE_TTL_MS): boolean {
    this.gc()
    if (this.nonces.size >= MAX_LIVE_NONCES) return false
    this.nonces.set(nonce, { expires: this.now() + ttlMs, used: false, uri })
    return true
  }

  /**
   * The challenge URI issued for a nonce, live or already consumed. For
   * diagnostics only — a consumed record still holds it, which is exactly when
   * it is wanted.
   */
  issued(nonce: string): string | undefined {
    return this.nonces.get(nonce)?.uri
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
