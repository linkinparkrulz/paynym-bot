// SOCKS5 CONNECT, so the bot can reach a Dojo published as an onion service.
//
// Everything was originally assumed local, which is why nothing here existed:
// Soroban and the indexer sat on the same host and Tor was only configuration
// for the hidden service the bot EXPOSES. Reaching a *remote* Dojo inverts
// that, and Node has no SOCKS client — but the protocol is small enough that
// implementing it keeps the zero-dependency property intact.
//
// The important detail is ATYP=0x03 (domain name). The hostname is handed to
// Tor to resolve, so a .onion never reaches a system resolver — which both
// works at all (no DNS can resolve .onion) and avoids leaking which onion is
// being contacted to whatever the box uses for DNS.

import { connect } from 'node:net'
import type { Socket } from 'node:net'

export const DEFAULT_TOR_SOCKS_HOST = '127.0.0.1'
export const DEFAULT_TOR_SOCKS_PORT = 9050

export type SocksProxy = { host: string; port: number }

const VERSION = 0x05
const NO_AUTH = 0x00
const CMD_CONNECT = 0x01
const ATYP_DOMAIN = 0x03

// SOCKS5 reply codes (RFC 1928 §6), plus Tor's extensions in the 0x5b+ range.
const REPLY_MESSAGES: Record<number, string> = {
  0x00: 'succeeded',
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable — is the onion address correct and the service up?',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
}

/** Read exactly `n` bytes, or reject if the socket ends first. */
function readExactly(socket: Socket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0

    const onReadable = () => {
      for (;;) {
        const chunk = socket.read(Math.min(n - total, socket.readableLength || n - total))
        if (chunk === null) return
        chunks.push(chunk)
        total += chunk.length
        if (total >= n) {
          cleanup()
          resolve(Buffer.concat(chunks, n))
          return
        }
      }
    }
    const onEnd = () => {
      cleanup()
      reject(new Error('SOCKS proxy closed the connection mid-handshake'))
    }
    const onError = (err: Error) => {
      cleanup()
      reject(err)
    }
    const cleanup = () => {
      socket.removeListener('readable', onReadable)
      socket.removeListener('end', onEnd)
      socket.removeListener('error', onError)
    }

    socket.on('readable', onReadable)
    socket.once('end', onEnd)
    socket.once('error', onError)
    onReadable()
  })
}

/**
 * Open a TCP tunnel to `host:port` through a SOCKS5 proxy. The returned socket
 * is transparent from that point on, so protocol code above it is unchanged.
 */
export async function socksConnect(
  proxy: SocksProxy,
  host: string,
  port: number,
  timeoutMs = 30_000,
): Promise<Socket> {
  const hostname = Buffer.from(host, 'utf8')
  if (hostname.length > 255) throw new Error(`hostname too long for SOCKS5: ${host}`)

  const socket = connect({ host: proxy.host, port: proxy.port })

  const fail = (err: Error) => {
    socket.destroy()
    throw err
  }

  // One deadline over the WHOLE handshake, not just the TCP connect.
  // socket.setTimeout only *emits* 'timeout'; it aborts nothing. A proxy that
  // accepts and then goes silent would leave this pending forever — and callers
  // cache the pending promise, so the job wedges permanently while the process
  // still looks healthy enough that systemd never restarts it.
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_, reject) => {
    deadlineTimer = setTimeout(() => {
      socket.destroy()
      reject(new Error(`SOCKS handshake to ${host}:${port} timed out after ${timeoutMs}ms`))
    }, timeoutMs)
  })

  const handshake = async (): Promise<Socket> => {
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', resolve)
      socket.once('error', reject)
    })

    // Greeting: version, one method, "no authentication".
    socket.write(Buffer.from([VERSION, 0x01, NO_AUTH]))
    const greeting = await readExactly(socket, 2)
    if (greeting[0] !== VERSION) {
      return fail(new Error(`not a SOCKS5 proxy at ${proxy.host}:${proxy.port}`))
    }
    if (greeting[1] !== NO_AUTH) {
      return fail(new Error('SOCKS proxy demands authentication, which Tor does not use'))
    }

    // CONNECT by domain name, so Tor resolves it and .onion works at all.
    const request = Buffer.concat([
      Buffer.from([VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, hostname.length]),
      hostname,
      Buffer.from([(port >> 8) & 0xff, port & 0xff]),
    ])
    socket.write(request)

    const reply = await readExactly(socket, 4)
    if (reply[1] !== 0x00) {
      const why = REPLY_MESSAGES[reply[1]] ?? `SOCKS error 0x${reply[1].toString(16)}`
      return fail(new Error(`SOCKS connect to ${host}:${port} failed: ${why}`))
    }

    // Drain the bound address so the stream starts at the payload.
    const atyp = reply[3]
    if (atyp === 0x01) await readExactly(socket, 4 + 2)
    else if (atyp === 0x04) await readExactly(socket, 16 + 2)
    else if (atyp === ATYP_DOMAIN) {
      const len = await readExactly(socket, 1)
      await readExactly(socket, len[0] + 2)
    } else return fail(new Error(`SOCKS proxy replied with unknown address type ${atyp}`))

    return socket
  }

  try {
    return await Promise.race([handshake(), deadline])
  } catch (err) {
    socket.destroy()
    throw err
  } finally {
    clearTimeout(deadlineTimer)
  }
}
