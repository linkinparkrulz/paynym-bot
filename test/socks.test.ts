// SOCKS5, and the two clients running through it.
//
// The fake proxy below records exactly what was requested and then pipes to a
// real backend, so these tests prove three things at once: the handshake is
// well-formed, the .onion hostname is passed to the proxy UNRESOLVED (nothing
// else can resolve it, and resolving locally would leak it), and the tunnel is
// transparent to the protocol running on top.

import { createServer, connect } from 'node:net'
import { createServer as createHttpServer } from 'node:http'
import type { AddressInfo, Socket } from 'node:net'
import { ElectrumClient } from '../src/electrum.ts'
import { SorobanRPC } from '../src/soroban.ts'
import { socksConnect } from '../src/socks.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}
async function rejects(name: string, fn: () => Promise<unknown>, expect?: string): Promise<void> {
  try {
    await fn()
    assert(name, false)
  } catch (e) {
    assert(name, expect ? (e as Error).message.includes(expect) : true)
  }
}

type Requested = { atyp: number; host: string; port: number }
const requested: Requested[] = []

/** A SOCKS5 proxy that tunnels everything to one backend port. */
function fakeProxy(backendPort: number, reply = 0x00) {
  return createServer((client: Socket) => {
    let stage = 0
    let buf = Buffer.alloc(0)
    client.on('error', () => {})
    client.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk])
      if (stage === 0) {
        if (buf.length < 2) return
        const nMethods = buf[1]
        if (buf.length < 2 + nMethods) return
        buf = buf.subarray(2 + nMethods)
        client.write(Buffer.from([0x05, 0x00])) // version, no-auth
        stage = 1
      }
      if (stage === 1) {
        if (buf.length < 5) return
        const atyp = buf[3]
        const len = buf[4]
        if (buf.length < 5 + len + 2) return
        const host = buf.subarray(5, 5 + len).toString('utf8')
        const port = buf.readUInt16BE(5 + len)
        buf = buf.subarray(5 + len + 2)
        requested.push({ atyp, host, port })

        if (reply !== 0x00) {
          client.write(Buffer.from([0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
          client.end()
          stage = 3
          return
        }
        client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        stage = 2

        const upstream = connect({ host: '127.0.0.1', port: backendPort })
        upstream.on('error', () => client.destroy())
        upstream.on('connect', () => {
          if (buf.length > 0) upstream.write(buf)
          buf = Buffer.alloc(0)
          client.pipe(upstream)
          upstream.pipe(client)
        })
      }
    })
  })
}

// --- backends ---------------------------------------------------------------
const electrumBackend = createServer((socket) => {
  let buf = ''
  socket.setEncoding('utf8')
  socket.on('error', () => {})
  socket.on('data', (chunk: string) => {
    buf += chunk
    let nl: number
    while ((nl = buf.indexOf('\n')) >= 0) {
      const req = JSON.parse(buf.slice(0, nl))
      buf = buf.slice(nl + 1)
      const result =
        req.method === 'server.version' ? ['Fulcrum 1.9.1', '1.4'] : [{ tx_hash: 'ab', height: 1 }]
      socket.write(`${JSON.stringify({ id: req.id, result })}\n`)
    }
  })
})
await new Promise<void>((r) => electrumBackend.listen(0, '127.0.0.1', r))
const electrumPort = (electrumBackend.address() as AddressInfo).port

const sorobanBackend = createHttpServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    const { id } = JSON.parse(body)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result: { Name: 'x', Entries: ['hello'] } }))
  })
})
await new Promise<void>((r) => sorobanBackend.listen(0, '127.0.0.1', r))
const sorobanPort = (sorobanBackend.address() as AddressInfo).port

// --- handshake --------------------------------------------------------------
const proxyToElectrum = fakeProxy(electrumPort)
await new Promise<void>((r) => proxyToElectrum.listen(0, '127.0.0.1', r))
const proxy = { host: '127.0.0.1', port: (proxyToElectrum.address() as AddressInfo).port }

const ONION = 'jfvhxw2xziznrthfhxnk45e7whvkb2gwmzh3ejqblcrbx4ah6ijo27yd.onion'

const tunnel = await socksConnect(proxy, ONION, 50001)
assert('the tunnel opens', !tunnel.destroyed)
assert('CONNECT used the domain address type (0x03)', requested[0].atyp === 0x03)
assert('the onion hostname was passed through unresolved', requested[0].host === ONION)
assert('the port was carried big-endian', requested[0].port === 50001)
tunnel.destroy()

// --- Electrum over the tunnel ----------------------------------------------
const client = new ElectrumClient({ host: ONION, port: 50001, proxy, timeoutMs: 4000 })
assert('server.version answers through Tor', Array.isArray(await client.serverVersion()))
const before = requested.length
assert('a history query answers through Tor',
  (await client.isUsed('141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK', { p2pkhVersion: 0x00, coinType: 0 })) === true)
assert('the second call reused the tunnel', requested.length === before)
client.close()

// --- Soroban over the tunnel ------------------------------------------------
const proxyToSoroban = fakeProxy(sorobanPort)
await new Promise<void>((r) => proxyToSoroban.listen(0, '127.0.0.1', r))
const sProxy = { host: '127.0.0.1', port: (proxyToSoroban.address() as AddressInfo).port }

const rpc = SorobanRPC.forUrl(`http://${ONION}/rpc`, sProxy)
const entries = await rpc.list('probe')
assert('soroban answers through Tor', entries.length === 1 && entries[0] === 'hello')
assert('soroban used the onion hostname', requested.at(-1)?.host === ONION)
assert('soroban defaulted to port 80', requested.at(-1)?.port === 80)

// --- failures are clean, not hangs -----------------------------------------
const refusing = fakeProxy(electrumPort, 0x05) // "connection refused"
await new Promise<void>((r) => refusing.listen(0, '127.0.0.1', r))
const badProxy = { host: '127.0.0.1', port: (refusing.address() as AddressInfo).port }
await rejects('a refused CONNECT explains itself',
  () => socksConnect(badProxy, ONION, 50001), 'connection refused')

const unreachable = fakeProxy(electrumPort, 0x04) // "host unreachable"
await new Promise<void>((r) => unreachable.listen(0, '127.0.0.1', r))
await rejects('an unreachable onion explains itself',
  () => socksConnect({ host: '127.0.0.1', port: (unreachable.address() as AddressInfo).port }, ONION, 50001),
  'onion address correct')

await rejects('no proxy listening fails fast',
  () => socksConnect({ host: '127.0.0.1', port: 1 }, ONION, 50001))

for (const s of [electrumBackend, sorobanBackend, proxyToElectrum, proxyToSoroban, refusing, unreachable]) {
  await new Promise<void>((r) => s.close(() => r()))
}

console.log('')
if (failures === 0) {
  console.log('PASS — SOCKS5 tunnel: onion passed unresolved, transparent to both clients.')
} else {
  console.log(`FAIL — ${failures} socks check(s) failed.`)
  process.exit(1)
}
