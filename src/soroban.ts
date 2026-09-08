// Soroban transport, matching THIS repository's wire protocol exactly
// (see ../../../services/directory.go, ../../../internal/common/ttl.go and the
// reference clients under ../../../clients/).
//
// Wire summary:
//   * JSON-RPC 2.0 over HTTP POST to a node's /rpc endpoint (usually a .onion
//     reached through a Tor SOCKS proxy). Methods: directory.List / directory.Add
//     / directory.Remove, each taking a single object param.
//   * A "directory" is just a key string. Clients address it by its SHA256 hex
//     (encodeDirectory) so the node never sees the human-readable name.
//   * Entries are opaque strings with a TTL chosen by Mode:
//        fast=15s  short=1m  long=5m  default/normal=3m   (server caps at 15m)
//   * Channel confidentiality is NaCl crypto_box (Curve25519 / XSalsa20-Poly1305)
//     over EPHEMERAL keypairs generated per session. IMPORTANT: these are NOT the
//     BIP47 secp256k1 payment-code keys. Decrypting a Soroban message proves the
//     peer holds the ephemeral box key, and says nothing about any payment code.
//     Payment-code authenticity must be established at the application layer
//     (see register.ts).

import { request as httpRequest } from 'node:http'
import nacl from 'tweetnacl'
import { sha256 } from '@noble/hashes/sha256'
import { socksConnect } from './socks.ts'
import type { SocksProxy } from './socks.ts'

export type Mode = 'fast' | 'short' | 'default' | 'normal' | 'long'

function toHex(u8: Uint8Array): string {
  return Buffer.from(u8).toString('hex')
}
function fromHex(h: string): Uint8Array {
  return Uint8Array.from(Buffer.from(h, 'hex'))
}

/** encodeDirectory(name) = SHA256 hex of the UTF-8 name. */
export function encodeDirectory(name: string): string {
  if (!name) throw new Error('encodeDirectory: empty name')
  return toHex(sha256(new TextEncoder().encode(name)))
}

/**
 * A transport is anything that can POST a JSON-RPC payload and return the parsed
 * response object. The default uses global fetch. Inject your own to route over
 * a Tor SOCKS proxy (e.g. undici + socks-proxy-agent) or to test offline.
 */
export type RpcTransport = (payload: unknown) => Promise<any>

/**
 * Transport for a Soroban published as an onion service. Node's fetch (undici)
 * cannot speak SOCKS, so this drops to node:http and supplies the tunnelled
 * socket via createConnection. Soroban's hidden service is plain HTTP on port
 * 80 — Tor is the transport security — so there is no TLS to arrange.
 */
export function socksTransport(
  url: string,
  proxy: SocksProxy,
  timeoutMs = 30_000,
): RpcTransport {
  const target = new URL(url)
  const port = Number(target.port || 80)

  return (payload: unknown) =>
    new Promise((resolve, reject) => {
      const body = JSON.stringify(payload)
      const req = httpRequest(
        {
          host: target.hostname,
          port,
          path: `${target.pathname}${target.search}`,
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
            'user-agent': 'HotJava/1.1.2 FCS',
          },
          createConnection: ((_opts: unknown, cb: (e: Error | null, s?: unknown) => void) => {
            socksConnect(proxy, target.hostname, port, timeoutMs).then(
              (socket) => cb(null, socket),
              (err: Error) => cb(err),
            )
            // Returning nothing is valid when the callback form is used.
            return undefined
          }) as never,
        },
        (res) => {
          if (res.statusCode !== undefined && res.statusCode >= 400) {
            res.resume()
            reject(new Error(`Soroban RPC HTTP ${res.statusCode}`))
            return
          }
          let text = ''
          res.setEncoding('utf8')
          res.on('data', (c: string) => (text += c))
          res.on('end', () => {
            try {
              resolve(JSON.parse(text))
            } catch {
              reject(new Error('Soroban RPC returned invalid JSON'))
            }
          })
        },
      )
      // Same reasoning as the fetch path: a stalled node must not wedge a tick
      // forever, since the daemon skips a tick whose predecessor is running.
      req.setTimeout(timeoutMs, () => req.destroy(new Error('Soroban RPC timed out')))
      req.on('error', reject)
      req.end(body)
    })
}

export function fetchTransport(url: string, timeoutMs = 15_000): RpcTransport {
  return async (payload: unknown) => {
    // Without a deadline a stalled node wedges the caller forever. The daemon
    // skips a tick whose predecessor is still running, so one hung request
    // would silently stop that job for the life of the process.
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        // The reference clients spoof this User-Agent; kept for parity.
        'user-agent': 'HotJava/1.1.2 FCS',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) throw new Error(`Soroban RPC HTTP ${res.status}`)
    return res.json()
  }
}

export type ConfidentialAuth = {
  algorithm: 'nacl'
  publicKey: string // ed25519 public key hex (32 bytes)
  sign: (message: string) => string // detached ed25519 signature hex (64 bytes)
}

/** Build a ConfidentialAuth from a tweetnacl sign keypair secret key (64 bytes). */
export function naclSigner(signSecretKey: Uint8Array): ConfidentialAuth {
  const pub = signSecretKey.slice(32) // ed25519 public key is the tail of the secret key
  return {
    algorithm: 'nacl',
    publicKey: toHex(pub),
    sign: (message: string) =>
      toHex(nacl.sign.detached(new TextEncoder().encode(message), signSecretKey)),
  }
}

export class SorobanRPC {
  private transport: RpcTransport

  constructor(transport: RpcTransport) {
    this.transport = transport
  }

  /** Over Tor when `proxy` is given (an onion Dojo), directly otherwise. */
  static forUrl(url: string, proxy?: SocksProxy): SorobanRPC {
    return new SorobanRPC(proxy ? socksTransport(url, proxy) : fetchTransport(url))
  }

  private async call(method: string, args: Record<string, unknown>): Promise<any> {
    const resp = await this.transport({ jsonrpc: '2.0', id: 1, method, params: [args] })
    return resp && Object.hasOwn(resp, 'result') ? resp.result : null
  }

  /**
   * List entries under a directory key. For a confidential prefix the node
   * requires a signature; pass `auth` so it will return entries to us.
   */
  async list(name: string, auth?: ConfidentialAuth): Promise<string[]> {
    const args: Record<string, unknown> = { Name: name, Entries: [] }
    if (auth) {
      const timestamp = Date.now() * 1_000_000 // node expects nanoseconds
      args.PublicKey = auth.publicKey
      args.Algorithm = auth.algorithm
      args.Timestamp = timestamp
      args.Signature = auth.sign(`${name}.${timestamp}`)
    }
    const result = await this.call('directory.List', args)
    return result && Array.isArray(result.Entries) ? result.Entries : []
  }

  /** Add an entry under a directory key with the given TTL mode. */
  async add(name: string, entry: string, mode: Mode = 'default'): Promise<boolean> {
    const result = await this.call('directory.Add', { Name: name, Entry: entry, Mode: mode })
    return !!result && result.Status === 'success'
  }

  /** Remove an entry from a directory key. */
  async remove(name: string, entry: string): Promise<boolean> {
    const result = await this.call('directory.Remove', { Name: name, Entry: entry })
    return !!result && result.Status === 'success'
  }

  /**
   * Poll `list` until an entry appears, then remove and return the last one.
   * Mirrors waitAndRemove in the reference clients.
   */
  async waitAndRemove(
    name: string,
    opts: { tries?: number; intervalMs?: number; auth?: ConfidentialAuth } = {},
  ): Promise<string | null> {
    const tries = opts.tries ?? 25
    const intervalMs = opts.intervalMs ?? 200
    for (let i = 0; i < tries; i++) {
      const values = await this.list(name, opts.auth)
      if (values.length > 0) {
        const value = values[values.length - 1]
        await this.remove(name, value)
        return value
      }
      await new Promise((r) => setTimeout(r, intervalMs))
    }
    return null
  }
}

// --- Ephemeral NaCl box channel (matches the reference clients' User class) ---

export class BoxKeypair {
  readonly publicKey: Uint8Array
  readonly secretKey: Uint8Array

  private constructor(publicKey: Uint8Array, secretKey: Uint8Array) {
    this.publicKey = publicKey
    this.secretKey = secretKey
  }

  static generate(): BoxKeypair {
    const kp = nacl.box.keyPair()
    return new BoxKeypair(kp.publicKey, kp.secretKey)
  }

  publicKeyHex(): string {
    return toHex(this.publicKey)
  }

  /** Shared box key with a peer, hex-encoded (== the reference boxShared()). */
  sharedHex(peerPublicKey: Uint8Array): string {
    return toHex(nacl.box.before(peerPublicKey, this.secretKey))
  }

  /** Encrypt to peer; output is hex(nonce(24) || crypto_box). */
  encrypt(message: string, peerPublicKey: Uint8Array): string {
    const nonce = nacl.randomBytes(nacl.box.nonceLength)
    const box = nacl.box(new TextEncoder().encode(message), nonce, peerPublicKey, this.secretKey)
    const merged = new Uint8Array(nonce.length + box.length)
    merged.set(nonce)
    merged.set(box, nonce.length)
    return toHex(merged)
  }

  /** Decrypt hex(nonce(24) || crypto_box) from peer; null on failure. */
  decrypt(data: string, peerPublicKey: Uint8Array): string | null {
    const bytes = fromHex(data)
    const nonce = bytes.slice(0, nacl.box.nonceLength)
    const box = bytes.slice(nacl.box.nonceLength)
    const opened = nacl.box.open(box, nonce, peerPublicKey, this.secretKey)
    return opened ? new TextDecoder().decode(opened) : null
  }
}

export { toHex as hex, fromHex as unhex }
