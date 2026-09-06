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

import { createServer as createHttpServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Server } from 'node:http'
import type { PaynymIdentity } from './identity.ts'
import type { NetworkName } from './state.ts'

const PUBLIC_DIR = join(import.meta.dirname, '..', 'public')

export type StorefrontOptions = {
  identity: PaynymIdentity
  network: NetworkName
  /** Optional label shown above the payment code, e.g. a shop name. */
  label?: string
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
  }
}

export function createStorefront(opts: StorefrontOptions): Server {
  const index = readFileSync(join(PUBLIC_DIR, 'index.html'))

  return createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' }).end('method not allowed')
      return
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        // No external anything: the page must work with no clearnet access.
        'content-security-policy':
          "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
      })
      res.end(req.method === 'HEAD' ? undefined : index)
      return
    }

    if (url.pathname === '/api/status') {
      const body = JSON.stringify(publicStatus(opts))
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
      })
      res.end(req.method === 'HEAD' ? undefined : body)
      return
    }

    if (url.pathname === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok')
      return
    }

    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found')
  })
}
