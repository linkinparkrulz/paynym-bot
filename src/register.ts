// Notification-less BIP47 registration over Soroban.
//
// A BIP47 payment to a new counterparty normally costs TWO transactions: a
// notification transaction to connect, then the real payment. Between regulars
// that amortises. For a merchant it never does — every customer is a first
// payment — so the notification transaction is pure overhead on every
// one-time payer.
//
// The notification transaction is a mailbox for a recipient who might not be
// there. This receiver is always online, so the mailbox is unnecessary: the
// customer hands over their payment code directly, over Soroban, and both
// sides derive the same receive address.
//
// Two things must hold, and neither is provided by the transport:
//
//   Confidentiality — the customer's payment code must not be readable by
//     onlookers. Handled in ./channel.ts, which encrypts to the merchant's
//     child-0 key derived from the payment code the customer already has.
//     Nothing is published, so there is nothing for an attacker to substitute.
//
//   Authenticity — a submitted payment code must be proven to belong to
//     whoever sent it. Decrypting proves only that the sender could encrypt to
//     us, which anyone holding our public payment code can do. So the envelope
//     is SIGNED with the payment code's own identity key (secp256k1 child-0)
//     and verified against the pubkey embedded in the submitted code.

import { nodeFromPaymentCode } from './bip47.ts'
import { PaynymIdentity, verifyIdentitySignature } from './identity.ts'
import { openWithIdentityKey, sealToPaymentCode } from './channel.ts'
import { SorobanRPC, encodeDirectory, hex } from './soroban.ts'
import type { ConfidentialAuth, Mode } from './soroban.ts'

export const PROTOCOL = 'paynym.register'

// v2: the signed message now names the RECEIVER as well as the sender. Under
// v1 an envelope captured from one receiver replayed verbatim into any other,
// registering a customer with a merchant they never contacted. v1 envelopes are
// rejected rather than accepted for compatibility: both ends of this protocol
// are ours, so there is no legacy to carry.
export const PROTOCOL_VERSION = 2

// Replay window for a registration envelope.
const MAX_SKEW_MS = 6 * 60 * 60 * 1000 // 6 hours

export type RegisterEnvelope = {
  v: number
  type: string
  paymentCode: string
  ts: number
  sig: string // secp256k1 DER hex over sha256(signedMessage)
}

function signedMessage(
  receiverPaymentCode: string,
  senderPaymentCode: string,
  ts: number,
): Uint8Array {
  return new TextEncoder().encode(
    `${PROTOCOL}|${receiverPaymentCode}|${senderPaymentCode}|${ts}`,
  )
}

/** Identity pubkey (hex) that must have signed a registration for `paymentCode`. */
function identityKeyOf(paymentCode: string): string {
  return hex(nodeFromPaymentCode(paymentCode).deriveChild(0).publicKey!)
}

/** Customer: build a signed envelope disclosing our payment code to one merchant. */
export function buildRegisterEnvelope(
  sender: PaynymIdentity,
  receiverPaymentCode: string,
  ts = Date.now(),
): RegisterEnvelope {
  const paymentCode = sender.paymentCode()
  return {
    v: PROTOCOL_VERSION,
    type: PROTOCOL,
    paymentCode,
    ts,
    sig: sender.signIdentity(signedMessage(receiverPaymentCode, paymentCode, ts)),
  }
}

/** Merchant: validate an envelope addressed to us. Returns the payment code, or null. */
export function verifyRegisterEnvelope(
  env: RegisterEnvelope,
  receiverPaymentCode: string,
  now = Date.now(),
): string | null {
  if (!env || env.type !== PROTOCOL || env.v !== PROTOCOL_VERSION) return null
  if (typeof env.paymentCode !== 'string' || typeof env.sig !== 'string') return null
  if (typeof env.ts !== 'number' || Math.abs(now - env.ts) > MAX_SKEW_MS) return null
  let identityKey: string
  try {
    identityKey = identityKeyOf(env.paymentCode)
  } catch {
    return null
  }
  const ok = verifyIdentitySignature(
    identityKey,
    signedMessage(receiverPaymentCode, env.paymentCode, env.ts),
    env.sig,
  )
  return ok ? env.paymentCode : null
}

// --- Directory addressing ---------------------------------------------------
//
// `plain` works on any node; contents are encrypted so listers see ciphertext.
// `confidential` additionally hides the queue behind the node's
// `soroban.register-queue.*` prefix, whose List requires an Ed25519 signature —
// worth using when you run the node, which a Dojo-side deployment does.

export type Scheme = 'plain' | 'confidential'

export function inboxName(receiverPaymentCode: string, scheme: Scheme = 'plain'): string {
  if (scheme === 'confidential') {
    return `soroban.register-queue.in.${encodeDirectory(receiverPaymentCode)}`
  }
  return encodeDirectory(`${PROTOCOL}.inbox.${receiverPaymentCode}`)
}

// --- Registry ---------------------------------------------------------------

export type SenderRecord = {
  paymentCode: string
  label?: string
  firstSeen: number
  nextIndex: number // next receive index we expect to be unused
}

/**
 * The customers who have registered with us. This is key material: receive keys
 * cannot be re-derived from the seed alone, because a BIP47 address depends on
 * BOTH parties' payment codes. Persist it alongside the seed.
 */
export class Registry {
  private records = new Map<string, SenderRecord>()

  has(paymentCode: string): boolean {
    return this.records.has(paymentCode)
  }
  get(paymentCode: string): SenderRecord | undefined {
    return this.records.get(paymentCode)
  }
  all(): SenderRecord[] {
    return [...this.records.values()]
  }
  /** Add a sender if new. Returns true if this was a new registration. */
  add(paymentCode: string, label?: string, now = Date.now()): boolean {
    if (this.records.has(paymentCode)) return false
    this.records.set(paymentCode, { paymentCode, label, firstSeen: now, nextIndex: 0 })
    return true
  }
  /** Advance a sender's cursor after crediting a payment at `index`. */
  advance(paymentCode: string, usedIndex: number): void {
    const rec = this.records.get(paymentCode)
    if (rec && usedIndex >= rec.nextIndex) rec.nextIndex = usedIndex + 1
  }

  toJSON(): SenderRecord[] {
    return this.all()
  }
  static fromJSON(records: SenderRecord[]): Registry {
    const r = new Registry()
    for (const rec of records) r.records.set(rec.paymentCode, rec)
    return r
  }
}

// --- Customer side ----------------------------------------------------------

/**
 * Register our payment code with a merchant so they can watch for our payments,
 * with no notification transaction. The merchant's payment code — read from
 * their onion page — is the only input needed: it yields both the inbox to post
 * to and the key to encrypt under. Returns true if the Add succeeded.
 */
export async function registerWithReceiver(
  rpc: SorobanRPC,
  sender: PaynymIdentity,
  receiverPaymentCode: string,
  opts: { scheme?: Scheme; mode?: Mode } = {},
): Promise<boolean> {
  const envelope = JSON.stringify(buildRegisterEnvelope(sender, receiverPaymentCode))
  const sealed = sealToPaymentCode(receiverPaymentCode, envelope)
  return rpc.add(inboxName(receiverPaymentCode, opts.scheme ?? 'plain'), sealed, opts.mode ?? 'long')
}

// --- Merchant side ----------------------------------------------------------

/**
 * The always-online receiver. Holds the registry and drains the inbox. There is
 * no rendezvous key to publish and no box keypair to persist: the channel key
 * comes from our own payment code, which customers already have.
 */
export class Registrar {
  readonly identity: PaynymIdentity
  readonly registry: Registry
  private readonly scheme: Scheme
  private readonly auth?: ConfidentialAuth
  private rejectCount = 0

  constructor(
    identity: PaynymIdentity,
    registry: Registry = new Registry(),
    opts: { scheme?: Scheme; auth?: ConfidentialAuth } = {},
  ) {
    this.identity = identity
    this.registry = registry
    this.scheme = opts.scheme ?? 'plain'
    if (this.scheme === 'confidential' && !opts.auth) {
      throw new Error('confidential scheme requires a ConfidentialAuth (node ed25519 key)')
    }
    this.auth = opts.auth
  }

  /** The directory customers post their registrations to. */
  inbox(): string {
    return inboxName(this.identity.paymentCode(), this.scheme)
  }

  /**
   * Drain the inbox: decrypt, verify signatures, register new customers.
   * Returns the payment codes newly added this call.
   *
   * Durability: a registration is only reported after `onAccepted` resolves,
   * and the entry is only removed after that. If `onAccepted` throws, the
   * exception propagates BEFORE the removal, so the only remaining copy
   * survives to be re-ingested next tick (idempotent: Registry.add returns
   * false for a code it already holds).
   */
  async poll(
    rpc: SorobanRPC,
    opts: { onAccepted?: (paymentCode: string) => Promise<void> } = {},
  ): Promise<string[]> {
    const name = this.inbox()
    const entries = await rpc.list(name, this.auth)
    const added: string[] = []
    for (const entry of entries) {
      const paymentCode = this.ingest(entry)
      if (!paymentCode) {
        // Malformed or unverifiable: count it, remove it, continue. A bad entry
        // must never pin the queue. Never log the ciphertext.
        this.rejectCount++
      } else if (this.registry.add(paymentCode)) {
        if (opts.onAccepted) await opts.onAccepted(paymentCode) // durable before removal
        added.push(paymentCode)
      }
      await rpc.remove(name, entry)
    }
    return added
  }

  /** Number of inbox entries rejected for failing to decrypt or verify. */
  rejected(): number {
    return this.rejectCount
  }

  /** Decrypt + verify a single sealed inbox entry. Returns the payment code or null. */
  ingest(sealed: string): string | null {
    const plaintext = openWithIdentityKey(this.identity.identityPrivateKey(), sealed)
    if (!plaintext) return null
    let env: RegisterEnvelope
    try {
      env = JSON.parse(plaintext)
    } catch {
      return null
    }
    return verifyRegisterEnvelope(env, this.identity.paymentCode())
  }
}
