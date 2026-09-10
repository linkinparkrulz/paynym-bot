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
import { openSamourai } from './samourai.ts'
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

/**
 * The directory a stock Samourai/Ashigaru client writes to: SHA256 of the BARE
 * payment code, with no prefix (RpcDialog.encodeDirectory, seeded with
 * paymentCodePartner.toString()). We listen here too, or such a wallet could
 * never reach us.
 */
export function samouraiInboxName(receiverPaymentCode: string): string {
  return encodeDirectory(receiverPaymentCode)
}

// --- Registry ---------------------------------------------------------------

export type SenderRecord = {
  paymentCode: string
  label?: string
  firstSeen: number
  /**
   * First index never seen used. Everything BELOW this is known used; the
   * sparse indices at or above it that are known used live in `usedAhead`.
   */
  nextIndex: number
  /** Known-used indices above the cursor, ascending. Normally empty. */
  usedAhead?: number[]
}

/**
 * Ceiling on registered senders.
 *
 * Registration is open by design — the payment code is published and anyone
 * may send — and it costs an attacker nothing to generate payment codes, so
 * without a ceiling the watch list is an unauthenticated write. Every sender
 * adds `gap` addresses to each scan pass, so an unbounded list stops the
 * receiver from noticing real payments long before it exhausts memory.
 *
 * 10,000 senders is 50,000 watched addresses at the default gap: far more than
 * a self-hosted shop will see, and still a bounded scan.
 */
export const MAX_SENDERS = 10_000

/**
 * How long a registration that has never been paid is kept.
 *
 * Pruning these is what keeps a flood from being permanent. It is safe in the
 * way that matters — a record with no payment at any watched index has no
 * money behind it, so nothing becomes unspendable — but it is not free: a
 * customer who registers, waits longer than this, and only then pays would
 * find their payment unwatched until they register again. 30 days is chosen to
 * make that essentially theoretical for a shopping visit.
 */
export const UNPAID_TTL_MS = 30 * 24 * 60 * 60 * 1000

/**
 * The customers who have registered with us. This is key material: receive keys
 * cannot be re-derived from the seed alone, because a BIP47 address depends on
 * BOTH parties' payment codes. Persist it alongside the seed.
 */
export class Registry {
  private records = new Map<string, SenderRecord>()
  private readonly capacity: number

  constructor(capacity: number = MAX_SENDERS) {
    this.capacity = capacity
  }

  size(): number {
    return this.records.size
  }

  /** True when no further NEW sender can be accepted. See MAX_SENDERS. */
  isFull(): boolean {
    return this.records.size >= this.capacity
  }

  has(paymentCode: string): boolean {
    return this.records.has(paymentCode)
  }
  get(paymentCode: string): SenderRecord | undefined {
    return this.records.get(paymentCode)
  }
  all(): SenderRecord[] {
    return [...this.records.values()]
  }
  /**
   * Add a sender if new. Returns true if this was a new registration.
   *
   * Refuses once full: callers that care about the difference between "already
   * known" and "no room" should check `isFull()` first, which is what the
   * storefront does so it can say so in its response.
   */
  add(paymentCode: string, label?: string, now = Date.now()): boolean {
    if (this.records.has(paymentCode)) return false
    if (this.isFull()) return false
    this.records.set(paymentCode, { paymentCode, label, firstSeen: now, nextIndex: 0 })
    return true
  }

  /**
   * Drop registrations that have never been paid and are older than `ttlMs`,
   * oldest first. Returns the codes removed.
   *
   * "Never paid" is exact, not a guess: `nextIndex === 0` with an empty
   * `usedAhead` means no index has ever been seen used, so no money has
   * arrived at any address this sender's code derives. A sender with any
   * payment history is never pruned, whatever its age — see `remove`.
   */
  pruneUnpaid(ttlMs = UNPAID_TTL_MS, now = Date.now()): string[] {
    const cutoff = now - ttlMs
    const stale = this.all()
      .filter((r) => r.nextIndex === 0 && (r.usedAhead ?? []).length === 0 && r.firstSeen < cutoff)
      .sort((a, b) => a.firstSeen - b.firstSeen)
    for (const r of stale) this.records.delete(r.paymentCode)
    return stale.map((r) => r.paymentCode)
  }
  /**
   * Drop a sender. Used only to undo an add whose persistence failed — see
   * Registrar.poll. Never call this to "forget" a real customer: their payment
   * code is required to derive addresses money may already have arrived at.
   */
  remove(paymentCode: string): void {
    this.records.delete(paymentCode)
  }
  /**
   * Record that `usedIndex` has been paid, and advance the cursor across any
   * CONTIGUOUS run of used indices.
   *
   * The cursor must not simply jump past the highest index seen. Customers pay
   * out of order — a wallet can skip an index, or a payment can confirm late —
   * and a cursor that leapt to `usedIndex + 1` abandoned every gap beneath it,
   * so a later payment to a skipped index was never watched for and silently
   * went unnoticed. This is the standard gap-limit rule instead.
   */
  advance(paymentCode: string, usedIndex: number): void {
    const rec = this.records.get(paymentCode)
    if (!rec || usedIndex < rec.nextIndex) return // already accounted for
    const ahead = new Set(rec.usedAhead ?? [])
    ahead.add(usedIndex)
    while (ahead.has(rec.nextIndex)) {
      ahead.delete(rec.nextIndex)
      rec.nextIndex++
    }
    rec.usedAhead = [...ahead].sort((a, b) => a - b)
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
  private deferredCount = 0

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

  /** Every directory we drain: ours, plus the one stock wallets use. */
  inboxes(): string[] {
    return [this.inbox(), samouraiInboxName(this.identity.paymentCode())]
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
    const added: string[] = []
    for (const name of this.inboxes()) {
      const entries = await rpc.list(name, this.auth)
      for (const entry of entries) {
        const paymentCode = this.ingest(entry)
        if (!paymentCode) {
          // Malformed or unverifiable: count it, remove it, continue. A bad
          // entry must never pin the queue. Never log the ciphertext.
          this.rejectCount++
        } else if (this.registry.has(paymentCode)) {
          // Already known. Idempotent: fall through and drop the entry.
        } else if (this.registry.isFull()) {
          // Valid, but there is no room on the watch list. Unlike a malformed
          // entry this one deserves to be kept: leave it in the inbox (skip
          // the removal below) so it is accepted as soon as a stale unpaid
          // registration is pruned. Its own directory TTL bounds how long it
          // can sit there.
          this.deferredCount++
          continue
        } else if (this.registry.add(paymentCode)) {
          try {
            if (opts.onAccepted) await opts.onAccepted(paymentCode) // durable before removal
          } catch (err) {
            // Undo the in-memory add. Without this the next tick sees the
            // customer as already known, skips persistence entirely, and then
            // removes the only durable copy — losing the payment code, and with
            // it the ability to derive addresses money may already sit at.
            this.registry.remove(paymentCode)
            throw err
          }
          added.push(paymentCode)
        }
        await rpc.remove(name, entry)
      }
    }
    return added
  }

  /** Number of inbox entries rejected for failing to decrypt or verify. */
  rejected(): number {
    return this.rejectCount
  }

  /**
   * Number of valid registrations left in the inbox because the watch list was
   * full. Non-zero means real customers are waiting on a prune.
   */
  deferred(): number {
    return this.deferredCount
  }

  /**
   * Decrypt + verify a single inbox entry, in either wire format. Returns the
   * customer's payment code, or null.
   *
   * The two formats authenticate differently, and the difference is the reason
   * the Samourai path needs no inner signature:
   *
   *   Samourai — the payload is encrypted under a STATIC-STATIC ECDH between
   *     our notification key and the claimed sender's. Forging one would need
   *     the claimed sender's PRIVATE key, so a payload whose HMAC verifies
   *     could only have been produced by the holder of that payment code.
   *     Successful decryption is itself the proof of identity.
   *
   *   Ours — the payload is encrypted to us under an EPHEMERAL key, so anyone
   *     holding our (published) payment code can seal to us. Decryption proves
   *     nothing about who sent it, which is exactly why that path additionally
   *     requires the signed envelope below.
   */
  ingest(sealed: string): string | null {
    const samourai = openSamourai(this.identity.identityPrivateKey(), sealed)
    if (samourai) return samourai.sender

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
