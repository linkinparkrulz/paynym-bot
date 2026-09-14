// Register this receiver's payment code with the PayNym directory (paynym.rs).
//
// A PayNym is only discoverable — name, avatar, the social graph — once the
// directory knows the payment code. The bot owns its key material, so it can
// do the whole dance itself:
//
//   POST /create    publish the code (idempotent: re-posting is fine)
//   POST /token     get a 24h auth token
//   POST /claim     sign that token with the notification key to CLAIM the
//                   nym, which is what makes it ours in the directory
//
// The claim signature is a Bitcoin signed message over the token, exactly the
// format the notification address verifies against — the same
// bitcoinjs-message path the auth47 proof uses, in the other direction.
//
// The registration is OPTIONAL and never fatal: the directory is a
// clearnet-indexed social service, and a receiver whose operator would rather
// not appear in it must still run. Failure is logged, once, with the remedy.
//
// Grounded in the PayNym API reference (paymentcode.io/docs — "PayNym API"):
// base URL https://paynym.rs/api/v1/, JSON bodies, auth-token header.

import { BIP47Factory } from '@dojo-tools/bip47'
import { bitcoinMessageFactory } from '@dojo-tools/bitcoinjs-message'
import ecc from '@bitcoinerlab/secp256k1'
import { socksConnect } from './socks.ts'
import type { SocksProxy } from './socks.ts'

const bip47 = BIP47Factory(ecc)
const bitcoinjsMessage = bitcoinMessageFactory(ecc)

export const PAYNYM_API = 'https://paynym.rs/api/v1'

/**
 * Is the Tor SOCKS proxy listening? The registration is best routed through
 * Tor — the box has a proxy whenever remote-Dojo mode is in use — but a
 * loopback-only deployment may not, and clearnet registration must still
 * work. Probed with a real TCP connect, so a configured-but-dead proxy is
 * detected rather than assumed.
 */
export async function torSocksReachable(config: { torSocks: SocksProxy }): Promise<boolean> {
  const net = await import('node:net')
  return new Promise((resolve) => {
    const socket = net.connect({ host: config.torSocks.host, port: config.torSocks.port })
    const done = (ok: boolean) => {
      socket.destroy()
      resolve(ok)
    }
    socket.once('connect', () => done(true))
    socket.once('error', () => done(false))
    setTimeout(() => done(false), 2_000)
  })
}

export type PaynymRegistration = {
  /** The nymName the directory assigned, e.g. "+feebledegree29". */
  nymName?: string
  nymId?: string
  claimed: boolean
  at: number
}

export type RegisterOptions = {
  /** Route through Tor (the box always has a SOCKS proxy when remote Dojos are in use). */
  proxy?: SocksProxy
  /** Per-request timeout. Directory calls go over the clearnet or Tor; keep them short. */
  timeoutMs?: number
  apiUrl?: string
  /** Injected for tests. */
  fetchImpl?: typeof fetch
}

/**
 * One JSON POST to the directory. Returns the parsed body, or throws with the
 * HTTP status when the directory refuses.
 */
async function post(
  path: string,
  body: unknown,
  opts: RegisterOptions,
  headers: Record<string, string> = {},
): Promise<any> {
  const url = `${opts.apiUrl ?? PAYNYM_API}${path}`
  const doFetch = opts.fetchImpl ?? fetch

  // fetch() speaks http(s) natively; the SOCKS case is handled by the caller
  // through an https.Agent in Node's undici only if we had a dispatcher —
  // Node's global fetch does not do SOCKS. For Tor-routed registration we
  // tunnel manually: CONNECT via socksConnect, then speak HTTP/1.1 over the
  // socket. Simple enough here, since each call is one request-response pair.
  if (opts.proxy) return postOverTor(url, body, headers, opts)

  const res = await doFetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
  })
  const parsed = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(`paynym.rs ${path} answered ${res.status}: ${JSON.stringify(parsed).slice(0, 200)}`)
  }
  return parsed
}

/** Minimal HTTP/1.1 POST over an already-established SOCKS tunnel. */
async function postOverTor(
  url: string,
  body: unknown,
  headers: Record<string, string>,
  opts: RegisterOptions,
): Promise<any> {
  const u = new URL(url)
  const socket = await socksConnect(
    opts.proxy!,
    u.hostname,
    Number(u.port || 443),
    opts.timeoutMs ?? 15_000,
  )
  const timeout = opts.timeoutMs ?? 15_000
  try {
    // paynym.rs is https; over the Tor tunnel the TLS is end-to-end to the
    // directory and we deliberately do not pin a CA — same trust as fetch().
    const tls = await import('node:tls')
    const secure = tls.connect({ socket, servername: u.hostname })
    await new Promise<void>((resolve, reject) => {
      secure.once('secureConnect', resolve)
      secure.once('error', reject)
      setTimeout(() => reject(new Error('TLS handshake to paynym.rs timed out')), timeout)
    })

    const payload = Buffer.from(JSON.stringify(body))
    const req = [
      `POST ${u.pathname} HTTP/1.1`,
      `Host: ${u.hostname}`,
      'content-type: application/json',
      `content-length: ${payload.length}`,
      'connection: close',
      ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      '',
      '',
    ].join('\r\n')
    secure.write(req)
    secure.write(payload)

    const raw = await new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = []
      secure.on('data', (c: Buffer) => chunks.push(c))
      secure.on('end', () => resolve(Buffer.concat(chunks)))
      secure.on('error', reject)
      setTimeout(() => reject(new Error('paynym.rs response timed out')), timeout)
    })
    const text = raw.toString('utf8')
    const bodyStart = text.indexOf('\r\n\r\n')
    const status = Number(text.slice('HTTP/1.1 '.length, text.indexOf(' ')))
    const parsed = JSON.parse(text.slice(bodyStart + 4) || '{}')
    if (status >= 400) {
      throw new Error(`paynym.rs ${u.pathname} answered ${status}: ${JSON.stringify(parsed).slice(0, 200)}`)
    }
    return parsed
  } finally {
    socket.destroy()
  }
}

/**
 * Sign a message with the payment code's notification key, in the exact
 * format the directory verifies: a recoverable base64 Bitcoin signed message
 * against the notification address.
 */
export function signWithNotificationKey(
  seed: Uint8Array,
  message: string,
  opts: { coinType?: number } = {},
): string {
  const pc = bip47.fromSeed(seed)
  void opts
  const notificationPriv = pc.getNotificationPrivateKey()
  // Compressed key, standard prefix: 31+recid header byte, base64.
  return Buffer.from(bitcoinjsMessage.sign(message, notificationPriv, true)).toString('base64')
}

/**
 * Publish and claim this receiver's nym on paynym.rs. Idempotent: every step
 * is safe to re-run, and a nym already created or claimed comes back as-is.
 *
 * Returns what the directory now knows about the code.
 */
export async function registerWithPaynymRs(
  seed: Uint8Array,
  paymentCode: string,
  opts: RegisterOptions = {},
): Promise<PaynymRegistration> {
  // 1. Create the entry (idempotent).
  const created = await post('/create', { code: paymentCode }, opts)

  // 2. Token for authenticated calls (24h validity; we use it immediately).
  const token = await post('/token', { code: paymentCode }, opts)
  const authToken = token.token
  if (typeof authToken !== 'string' || authToken.length === 0) {
    throw new Error('paynym.rs /token did not return a token')
  }

  // 3. Claim: prove ownership by signing the token with the notification key.
  const signature = signWithNotificationKey(seed, authToken)
  const claimed = await post(
    '/claim',
    { signature },
    opts,
    { 'auth-token': authToken },
  )

  return {
    nymName: claimed.nymName ?? created.nymName,
    nymId: claimed.nymId ?? created.nymID ?? created.nymID,
    claimed: claimed.claimed === true,
    at: Date.now(),
  }
}
