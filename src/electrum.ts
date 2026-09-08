// Used-address oracle over the Electrum protocol.
//
// A Dojo bundles Fulcrum, which speaks Electrum over TCP (50001 plaintext).
// That protocol is newline-delimited JSON-RPC over a socket, so this needs
// node:net and nothing else — no API key or JWT dance as with Dojo's REST API,
// and no dependency. It also works against any electrs/Fulcrum, so the bot is
// not tied to a Dojo.
//
// Point this only at YOUR OWN indexer. The addresses queried here are the
// merchant's counterparty graph: anyone answering these queries learns who is
// paying the merchant and when. That is precisely what the notification
// transaction was leaking on-chain, so leaking it to a public Electrum server
// instead would give the whole exercise away.

import { connect } from 'node:net'
import type { Socket } from 'node:net'
import { sha256 } from '@noble/hashes/sha256'
import { base58check as base58checkFactory } from '@scure/base'
import type { Network } from './bip47.ts'
import type { UsedChecker } from './watcher.ts'
import { socksConnect } from './socks.ts'
import type { SocksProxy } from './socks.ts'

const base58check = base58checkFactory(sha256)

/**
 * Electrum addresses scripts by the SHA256 of the scriptPubKey, byte-reversed
 * and hex-encoded. For P2PKH the script is OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
 * OP_CHECKSIG = 76a914{hash160}88ac.
 */
export function addressToScriptHash(address: string, network: Network): string {
  const payload = base58check.decode(address)
  if (payload.length !== 21) throw new Error(`not a P2PKH address: ${address}`)
  if (payload[0] !== network.p2pkhVersion) {
    throw new Error(`address ${address} is not on the configured network`)
  }
  const script = new Uint8Array(25)
  script[0] = 0x76 // OP_DUP
  script[1] = 0xa9 // OP_HASH160
  script[2] = 0x14 // push 20
  script.set(payload.subarray(1), 3)
  script[23] = 0x88 // OP_EQUALVERIFY
  script[24] = 0xac // OP_CHECKSIG
  return Buffer.from(sha256(script)).reverse().toString('hex')
}

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void }

export type ElectrumOptions = {
  host: string
  port: number
  /** Per-request timeout. A hung indexer must not wedge the scan loop. */
  timeoutMs?: number
  /**
   * Route through a SOCKS5 proxy (Tor). Required to reach a Dojo published as
   * an onion service; omit it for a Dojo on the same host.
   */
  proxy?: SocksProxy
}

/**
 * Minimal Electrum client. One socket, reconnected lazily on demand; a dropped
 * connection fails the in-flight requests rather than hanging them, and the
 * next call reconnects.
 */
export class ElectrumClient {
  private socket: Socket | null = null
  private connecting: Promise<Socket> | null = null
  private pending = new Map<number, Pending>()
  private buffer = ''
  private nextId = 1
  private readonly opts: ElectrumOptions
  private readonly timeoutMs: number

  // Fields are declared and assigned explicitly: Node's --experimental-strip-types
  // erases types without generating code, so TypeScript parameter properties
  // (`constructor(private readonly opts: ...)`) are a syntax error at runtime.
  constructor(opts: ElectrumOptions) {
    this.opts = opts
    this.timeoutMs = opts.timeoutMs ?? 10_000
  }

  private failAll(err: Error): void {
    for (const p of this.pending.values()) p.reject(err)
    this.pending.clear()
  }

  private handleLine(line: string): void {
    if (line.length === 0) return
    let msg: { id?: number; result?: unknown; error?: { message?: string } }
    try {
      msg = JSON.parse(line)
    } catch {
      return // a server that speaks nonsense is not worth crashing over
    }
    if (typeof msg.id !== 'number') return // subscription push; we make none
    const p = this.pending.get(msg.id)
    if (!p) return
    this.pending.delete(msg.id)
    if (msg.error) p.reject(new Error(msg.error.message ?? 'electrum error'))
    else p.resolve(msg.result)
  }

  /** Wire up a connected socket. Identical whether it came via Tor or not. */
  private attach(socket: Socket): void {
    socket.setEncoding('utf8')
    socket.setKeepAlive(true, 30_000)
    this.socket = socket

    socket.on('error', (err) => {
      this.socket = null
      this.failAll(err)
    })
    socket.on('close', () => {
      this.socket = null
      this.failAll(new Error('electrum connection closed'))
    })
    socket.on('data', (chunk: string) => {
      this.buffer += chunk
      let nl: number
      while ((nl = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, nl)
        this.buffer = this.buffer.slice(nl + 1)
        this.handleLine(line)
      }
    })
  }

  private async ensureConnected(): Promise<Socket> {
    if (this.socket && !this.socket.destroyed) return this.socket
    if (this.connecting) return this.connecting

    // A SOCKS tunnel is transparent once established, so everything above this
    // point — the line protocol, the pending map — is identical either way.
    const open = this.opts.proxy
      ? socksConnect(this.opts.proxy, this.opts.host, this.opts.port, this.timeoutMs)
      : new Promise<Socket>((resolve, reject) => {
          const socket = connect({ host: this.opts.host, port: this.opts.port })
          const onError = (err: Error) => reject(err)
          socket.once('error', onError)
          socket.once('connect', () => {
            socket.removeListener('error', onError)
            resolve(socket)
          })
        })

    this.connecting = open
      .then((socket) => {
        this.connecting = null
        this.attach(socket)
        return socket
      })
      .catch((err: Error) => {
        this.socket = null
        this.connecting = null
        this.failAll(err)
        throw err
      })
    return this.connecting
  }

  async request(method: string, params: unknown[]): Promise<unknown> {
    const socket = await this.ensureConnected()
    const id = this.nextId++
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`electrum ${method} timed out after ${this.timeoutMs}ms`))
      }, this.timeoutMs)

      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer)
          resolve(v)
        },
        reject: (e) => {
          clearTimeout(timer)
          reject(e)
        },
      })
      socket.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
    })
  }

  /** Server banner; a cheap way to prove the endpoint really is an indexer. */
  async serverVersion(client = 'paynym-bot'): Promise<unknown> {
    return this.request('server.version', [client, '1.4'])
  }

  /** True if anything has ever paid this address, confirmed or in mempool. */
  async isUsed(address: string, network: Network): Promise<boolean> {
    const history = await this.request('blockchain.scripthash.get_history', [
      addressToScriptHash(address, network),
    ])
    return Array.isArray(history) && history.length > 0
  }

  close(): void {
    this.failAll(new Error('electrum client closed'))
    this.socket?.destroy()
    this.socket = null
  }
}

/** Adapt a client to the oracle the watcher expects. */
export function electrumUsedChecker(client: ElectrumClient, network: Network): UsedChecker {
  return (address: string) => client.isUsed(address, network)
}
