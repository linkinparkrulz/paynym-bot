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
  /** Override the host the challenge names (defaults to the request Host). */
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
function publicStatus(opts: StorefrontOptions) {
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
    auth47: opts.registry !== undefined,
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

  /** The origin a request arrived for — the onion when reached through Tor. */
  const originOf = (req: IncomingMessage): string => {
    const host = opts.onionHost ?? req.headers.host
    if (!host) throw new Error('no Host header')
    // Behind Tor the scheme is http (the onion provides the transport
    // security); on loopback during development it is http too.
    return `http://${host}`
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
      json(res, 200, publicStatus(opts))
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
      if (!opts.registry) return json(res, 503, { error: 'auth47 unavailable' })
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'POST' }).end()
        return
      }
      let origin: string
      try {
        origin = originOf(req)
      } catch {
        return json(res, 400, { error: 'no Host header' })
      }
      const nonce = newNonce()
      const expires = Date.now() + NONCE_TTL_MS
      const callback = `${origin}/api/auth47/callback`
      // r binds the proof to THIS storefront: a challenge minted elsewhere
      // must not authenticate here, and vice versa.
      const uri = challengeURI(nonce, Math.floor(expires / 1000), callback, origin)
      sessions.issue(nonce)
      json(res, 200, { nonce, uri, expires })
      return
    }

    if (url.pathname === '/api/auth47/callback') {
      if (!opts.registry) return json(res, 503, { error: 'auth47 unavailable' })
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'POST' }).end()
        return
      }
      let proof: unknown
      try {
        proof = JSON.parse(await readBody(req))
      } catch {
        return json(res, 400, { error: 'invalid JSON' })
      }

      // Structural + cryptographic check first.
      const v = verifyProof(proof, networkForAddress(opts.network))
      if (!v.ok) return json(res, 401, { error: v.error })

      // The proof must name this storefront in r (relay binding).
      const challenge = (proof as { challenge?: string }).challenge ?? ''
      let resource: string | null = null
      try {
        resource = new URL(challenge).searchParams.get('r')
      } catch {
        /* handled below */
      }
      let origin: string
      try {
        origin = originOf(req)
      } catch {
        return json(res, 400, { error: 'no Host header' })
      }
      if (!resource || !sameResource(resource, origin)) {
        return json(res, 401, { error: 'proof was signed for a different site' })
      }

      // Single-use nonce, consumed atomically.
      let nonce: string | null = null
      try {
        nonce = new URL(challenge).hostname
      } catch {
        /* handled below */
      }
      const rec = nonce ? sessions.take(nonce) : null
      if (!rec) return json(res, 401, { error: 'unknown or expired nonce' })

      // Register the customer, durably, BEFORE the session becomes usable.
      // Same ordering rule as the daemon's inbox drain: persist before the
      // outside world can observe the acceptance.
      opts.registry.add(v.paymentCode)
      if (opts.persist) await opts.persist()

      const sessionId = sessions.mint(v.paymentCode)
      if (nonce) sessions.claim(nonce, sessionId)
      json(res, 200, { ok: true })
      return
    }

    if (url.pathname === '/api/auth47/poll') {
      if (!opts.registry) return json(res, 503, { error: 'auth47 unavailable' })
      const nonce = url.searchParams.get('nonce')
      if (!nonce) return json(res, 400, { error: 'missing nonce' })
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
