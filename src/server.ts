// The storefront: a small HTTP server behind a Tor hidden service.
//
// Tor terminates the onion and forwards to this server over loopback, so
// nothing here speaks Tor or TLS — that is torrc's job, not this code's.
//
// PRIVACY: this endpoint is public to anyone who has the onion address, so it
// exposes only what is already public — the merchant's payment code and which
// network it is on. It deliberately does NOT expose the registered customer
// payment codes, the watch list, or how many customers there are: that set is
// the merchant's counterparty graph and its size is their trading volume.
//
// THE SESSION FLOW is the exception, and it is deliberate: a customer who
// proves control of their payment code via Auth47 (a signature by the key the
// code itself names) may learn the receive address their code derives here —
// something they could compute themselves from the public payment code. The
// proof is what gates it: without one, an unauthenticated visitor learns
// nothing beyond the storefront's own code.

import { createServer as createHttpServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import type { PaynymIdentity } from './identity.ts'
import type { Registry } from './register.ts'
import type { NetworkName } from './state.ts'
import type { Network } from './bip47.ts'
import {
  Auth47Sessions,
  challengeURI,
  newNonce,
  sameResource,
  verifyProof,
  NONCE_TTL_MS,
} from './auth47.ts'

const PUBLIC_DIR = join(import.meta.dirname, '..', 'public')

/** Bodies are tiny JSON; anything larger is hostile before it is parsed. */
const MAX_BODY_BYTES = 8192

/**
 * Token-bucket limits for the two unauthenticated auth47 endpoints. There is
 * no client address to key on — every request arrives from Tor's loopback
 * forward — so these are deliberately GLOBAL buckets. That means a flood can
 * slow real customers down; it cannot make the receiver stop noticing their
 * payments, which is the failure that actually costs money. The registry cap
 * in ./register.ts is the hard bound behind these.
 *
 * Sized for humans: a burst covers a shop's worth of simultaneous shoppers,
 * and the sustained rate is far above any real arrival rate and far below what
 * it takes to bloat the watch list.
 */
export const CHALLENGE_BURST = 60
export const CHALLENGE_PER_SEC = 2
export const CALLBACK_BURST = 20
export const CALLBACK_PER_SEC = 0.5

/**
 * A leaky bucket. Returns a function that yields false when the caller has run
 * out of allowance, refilling continuously at `perSec`.
 */
function tokenBucket(capacity: number, perSec: number, now: () => number = Date.now) {
  let tokens = capacity
  let last = now()
  return (): boolean => {
    const t = now()
    tokens = Math.min(capacity, tokens + ((t - last) / 1000) * perSec)
    last = t
    if (tokens < 1) return false
    tokens -= 1
    return true
  }
}

/**
 * Normalise a Host header, or a configured host, for comparison: lowercase,
 * trimmed, with an explicit default port dropped so `shop.onion` and
 * `shop.onion:80` are the same host.
 */
function hostKey(host: string): string {
  return host.trim().toLowerCase().replace(/:80$/, '')
}

export type StorefrontOptions = {
  identity: PaynymIdentity
  network: NetworkName
  /** Optional label shown above the payment code, e.g. a shop name. */
  label?: string
  /**
   * Auth47 + session flow. When absent (plain `serve` before init), the
   * auth endpoints return 503 and the page degrades to the payment code.
   */
  registry?: Registry
  /** Must not resolve until the registry is durable. */
  persist?: () => Promise<void>
  /**
   * The host this storefront is published as — normally the .onion.
   *
   * REQUIRED for the auth47 flow, and the reason is the whole security
   * property of that flow. An auth47 proof is bound to a resource (`r`) so
   * that a proof signed for one site cannot authenticate at another. If the
   * resource is derived from the request's own Host header, the binding is
   * chosen by the caller and buys nothing: an attacker mints a challenge from
   * THIS server with a spoofed Host, so `c` and `r` both name the attacker's
   * site, has a victim's wallet sign it, and relays the proof back here — the
   * comparison passes because both halves are the attacker's string.
   *
   * So the origin comes from the operator, and a request whose Host does not
   * match it is refused. With no host configured the auth47 endpoints are not
   * served at all: this control has no safe default.
   */
  onionHost?: string
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(payload)
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

/**
 * Public view of the receiver. Everything here is safe to hand to a stranger:
 * a payment code is meant to be published, and the network is needed to avoid
 * paying the wrong chain.
 */
function publicStatus(opts: StorefrontOptions, auth47Available: boolean) {
  return {
    paymentCode: opts.identity.paymentCode(),
    network: opts.network,
    label: opts.label ?? null,
    // Stated explicitly so a customer can see the claim the site is making.
    notificationTransactionRequired: false,
    // Honest disclosure, not a footnote. A stock Samourai/Ashigaru wallet uses
    // a transport whose envelope carries the sender's payment code in
    // cleartext, so paying that way publishes "this person is a customer of
    // this shop" to anyone who can list the directory. Our own sender tool
    // encrypts under an ephemeral key and reveals nothing.
    stockWalletPublishesPaymentCode: true,
    // Whether the scan-to-pay session flow is available on this instance.
    // Needs both a registry and a configured published host — see onionHost.
    auth47: auth47Available,
  }
}

export function createStorefront(opts: StorefrontOptions): Server {
  const index = readFileSync(join(PUBLIC_DIR, 'index.html'))
  const qrScript = readFileSync(join(PUBLIC_DIR, 'js', 'qrcode.js'))
  const sessions = new Auth47Sessions()
  const networkForAddress = (name: NetworkName): Network =>
    name === 'mainnet'
      ? // Local import to avoid a circular dependency on state.ts helpers.
        { p2pkhVersion: 0x00, coinType: 0 }
      : { p2pkhVersion: 0x6f, coinType: 1 }

  // The host the operator published this storefront as, if they configured
  // one. Everything auth47 does is bound to it; see StorefrontOptions.
  const publishedHost = opts.onionHost ? hostKey(opts.onionHost) : undefined
  const auth47Available = opts.registry !== undefined && publishedHost !== undefined

  /**
   * The origin auth47 proofs are bound to: always the configured host, never
   * the request's. Returns null when the request was addressed to some other
   * host, which the caller must refuse — that mismatch IS the relay attack.
   */
  const originOf = (req: IncomingMessage): string | null => {
    if (publishedHost === undefined) return null
    const sent = req.headers.host
    if (sent === undefined || hostKey(sent) !== publishedHost) return null
    // Behind Tor the scheme is http: the onion provides the transport
    // security, so there is no TLS to name here.
    return `http://${publishedHost}`
  }

  const challengeAllowance = tokenBucket(CHALLENGE_BURST, CHALLENGE_PER_SEC)
  const callbackAllowance = tokenBucket(CALLBACK_BURST, CALLBACK_PER_SEC)

  /**
   * Shared preamble for the auth47 endpoints: is the flow available at all,
   * and is this request even addressed to us? 421 is exactly right for the
   * second — this server is not authoritative for the host that was asked
   * for — and it keeps the refusal legible in a log.
   */
  const auth47Origin = (req: IncomingMessage, res: ServerResponse): string | null => {
    if (!auth47Available) {
      json(res, 503, { error: 'auth47 unavailable' })
      return null
    }
    const origin = originOf(req)
    if (origin === null) {
      json(res, 421, { error: 'request was not addressed to this storefront' })
      return null
    }
    return origin
  }

  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    void handle(url, req, res).catch((err) => {
      if (!res.headersSent) json(res, 500, { error: 'internal' })
      res.end()
      console.error('[storefront]', err)
    })
  })

  async function handle(
    url: URL,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    // --- public, unauthenticated ------------------------------------------------
    if (url.pathname === '/' || url.pathname === '/index.html') {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { allow: 'GET, HEAD' }).end('method not allowed')
        return
      }
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        // No external anything: the page must work with no clearnet access.
        'content-security-policy':
          "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline' 'self'; connect-src 'self'",
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
      })
      res.end(req.method === 'HEAD' ? undefined : index)
      return
    }

    // The vendored QR generator the page loads from itself. One file, served
    // from this directory only — no directory listing, nothing else in /js.
    if (url.pathname === '/js/qrcode.js') {
      res.writeHead(200, {
        'content-type': 'application/javascript; charset=utf-8',
        'cache-control': 'public, max-age=86400',
        'x-content-type-options': 'nosniff',
      })
      res.end(req.method === 'HEAD' ? undefined : qrScript)
      return
    }

    if (url.pathname === '/api/status') {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { allow: 'GET, HEAD' }).end('method not allowed')
        return
      }
      json(res, 200, publicStatus(opts, auth47Available))
      return
    }

    if (url.pathname === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok')
      return
    }

    // --- auth47: challenge, callback, poll --------------------------------------
    // The wallet POSTs the proof to the callback; the browser polls with the
    // nonce it issued. Two different parties, one shared nonce.

    if (url.pathname === '/api/auth47/challenge') {
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'POST' }).end()
        return
      }
      const origin = auth47Origin(req, res)
      if (origin === null) return
      if (!challengeAllowance()) {
        return json(res, 429, { error: 'too many challenges, try again shortly' })
      }
      const nonce = newNonce()
      const expires = Date.now() + NONCE_TTL_MS
      const callback = `${origin}/api/auth47/callback`
      // r binds the proof to THIS storefront: a challenge minted elsewhere
      // must not authenticate here, and vice versa.
      const uri = challengeURI(nonce, Math.floor(expires / 1000), callback, origin)
      if (!sessions.issue(nonce)) {
        return json(res, 503, { error: 'too many challenges in flight' })
      }
      json(res, 200, { nonce, uri, expires })
      return
    }

    if (url.pathname === '/api/auth47/callback') {
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'POST' }).end()
        return
      }
      const origin = auth47Origin(req, res)
      if (origin === null) return
      // auth47Origin only yields an origin when a registry is present; this
      // restates that rather than asserting it, so the invariant is local.
      const registry = opts.registry
      if (!registry) return json(res, 503, { error: 'auth47 unavailable' })
      if (!callbackAllowance()) {
        return json(res, 429, { error: 'too many proofs, try again shortly' })
      }
      let proof: unknown
      try {
        proof = JSON.parse(await readBody(req))
      } catch {
        return json(res, 400, { error: 'invalid JSON' })
      }

      // Parse out the nonce and gate on it FIRST. It is a Map lookup, and it
      // is the real gate; verifyProof costs an ECDSA recovery plus a base58
      // encode on input nobody has authenticated yet. peek() deliberately
      // does not consume, so a wallet that submits a malformed proof cannot
      // burn the customer's own challenge.
      const challenge = typeof (proof as { challenge?: unknown }).challenge === 'string'
        ? (proof as { challenge: string }).challenge
        : ''
      let nonce: string | null = null
      let resource: string | null = null
      try {
        const u = new URL(challenge)
        if (u.protocol === 'auth47:') {
          nonce = u.hostname
          resource = u.searchParams.get('r')
        }
      } catch {
        /* handled by the nonce check below */
      }
      if (nonce === null || !sessions.peek(nonce)) {
        return json(res, 401, { error: 'unknown or expired nonce' })
      }

      // The proof must name this storefront in r (relay binding). `origin` is
      // the operator's configured host, so this comparison is meaningful.
      if (!resource || !sameResource(resource, origin)) {
        return json(res, 401, { error: 'proof was signed for a different site' })
      }

      // Structural + cryptographic check.
      const v = verifyProof(proof, networkForAddress(opts.network))
      if (!v.ok) return json(res, 401, { error: v.error })

      // Consume the nonce: single-use, and only now that the proof is good.
      const rec = sessions.take(nonce)
      if (!rec) return json(res, 401, { error: 'unknown or expired nonce' })

      // Refuse a NEW customer once the watch list is full rather than growing
      // without bound. An already-registered customer is always let through:
      // they may have money at an address we are already watching.
      if (!registry.has(v.paymentCode) && registry.isFull()) {
        return json(res, 503, { error: 'this receiver is not accepting new customers' })
      }

      // Register the customer, durably, BEFORE the session becomes usable.
      // Same ordering rule as the daemon's inbox drain: persist before the
      // outside world can observe the acceptance — and undo the in-memory add
      // if that persist fails, or the watcher would be watching addresses
      // that do not survive a restart.
      if (registry.add(v.paymentCode) && opts.persist) {
        try {
          await opts.persist()
        } catch (err) {
          registry.remove(v.paymentCode)
          throw err
        }
      }

      const sessionId = sessions.mint(v.paymentCode)
      sessions.claim(nonce, sessionId)
      json(res, 200, { ok: true })
      return
    }

    if (url.pathname === '/api/auth47/poll') {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { allow: 'GET, HEAD' }).end('method not allowed')
        return
      }
      if (auth47Origin(req, res) === null) return
      const nonce = url.searchParams.get('nonce')
      if (!nonce) return json(res, 400, { error: 'missing nonce' })
      // Handed out once: see Auth47Sessions.claimed.
      const sid = sessions.claimed(nonce)
      if (!sid) return json(res, 202, { status: 'pending' })
      json(res, 200, { status: 'authenticated', sessionId: sid })
      return
    }

    // --- session: the authenticated customer's address ---------------------------

    if (url.pathname.startsWith('/api/session/')) {
      if (!opts.registry || !opts.persist) {
        return json(res, 503, { error: 'sessions unavailable' })
      }
      const sessionId = url.pathname.slice('/api/session/'.length)
      const session = sessions.session(sessionId)
      if (!session) return json(res, 404, { error: 'no such session' })

      const record = opts.registry.get(session.paymentCode)
      if (!record) return json(res, 404, { error: 'not registered' })

      // The current unused index: stable until a payment advances the cursor.
      // The customer's wallet derives the identical address when it pays, and
      // the watcher is already watching this window.
      const index = record.nextIndex
      const address = opts.identity.receiveAddress(session.paymentCode, index)
      // Deliberately NOT included: the spend key, the watch window, any other
      // customer's existence.
      json(res, 200, {
        paymentCode: session.paymentCode,
        index,
        address,
        network: opts.network,
      })
      return
    }

    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found')
  }

  return server
}
