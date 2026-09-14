// Finding the Dojo services, and failing usefully when they are not there.
//
// The important property is that reachability is PROVEN by a protocol exchange.
// A listening socket that is not Fulcrum must not be accepted, because it would
// fail later, deeper, and far less legibly.

import { createServer as createTcpServer } from 'node:net'
import { createServer as createHttpServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  candidatesFor,
  dockerGateway,
  dockerContainerIp,
  probeElectrum,
  probeSoroban,
  remedyFor,
  sorobanUrlFor,
} from '../src/discover.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

// A port nothing is listening on, for the "unreachable" candidates.
const DEAD = { host: '127.0.0.1', port: 1, why: 'nothing here' }

// --- a real Fulcrum-ish server ---------------------------------------------
const electrum = createTcpServer((socket) => {
  let buf = ''
  socket.setEncoding('utf8')
  socket.on('error', () => {})
  socket.on('data', (chunk: string) => {
    buf += chunk
    let nl: number
    while ((nl = buf.indexOf('\n')) >= 0) {
      const req = JSON.parse(buf.slice(0, nl))
      buf = buf.slice(nl + 1)
      socket.write(`${JSON.stringify({ id: req.id, result: ['Fulcrum 1.9.1', '1.4'] })}\n`)
    }
  })
})
await new Promise<void>((r) => electrum.listen(0, '127.0.0.1', r))
const electrumPort = (electrum.address() as AddressInfo).port

// A socket that accepts connections but speaks nothing. This is the case a
// port scan would wrongly accept.
const mute = createTcpServer((socket) => socket.on('error', () => {}))
await new Promise<void>((r) => mute.listen(0, '127.0.0.1', r))
const mutePort = (mute.address() as AddressInfo).port

// --- a Soroban-ish node -----------------------------------------------------
const soroban = createHttpServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    const { id } = JSON.parse(body)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result: { Name: 'x', Entries: [] } }))
  })
})
await new Promise<void>((r) => soroban.listen(0, '127.0.0.1', r))
const sorobanPort = (soroban.address() as AddressInfo).port

// --- electrum discovery -----------------------------------------------------
const live = { host: '127.0.0.1', port: electrumPort, why: 'test server' }

const found = await probeElectrum([DEAD, live])
assert('finds the reachable indexer', found.found?.port === electrumPort)
assert('records the failed candidate first', found.attempts[0].error !== undefined)
assert('stops once one answers', found.attempts.length === 2)

const none = await probeElectrum([DEAD])
assert('reports nothing found when unreachable', none.found === null)
assert('every attempt carries a reason', none.attempts.every((a) => a.error !== undefined))

// The mute socket is the important case: it accepts a connection but never
// speaks, so only a real protocol exchange rules it out.
const muteFirst = await probeElectrum([
  { host: '127.0.0.1', port: mutePort, why: 'accepts but says nothing' },
  live,
])
assert('a silent listener is rejected, not accepted', muteFirst.found?.port === electrumPort)

// --- soroban discovery ------------------------------------------------------
const sorobanLive = { host: '127.0.0.1', port: sorobanPort, why: 'test node' }
assert('builds the rpc url', sorobanUrlFor(sorobanLive) === `http://127.0.0.1:${sorobanPort}/rpc`)

const sFound = await probeSoroban([DEAD, sorobanLive])
assert('finds the reachable soroban', sFound.found?.port === sorobanPort)
assert('reports nothing when soroban is absent', (await probeSoroban([DEAD])).found === null)

// --- candidate ordering and docker degradation ------------------------------
const candidates = await candidatesFor('fulcrum', 50001)
assert('loopback is always tried first', candidates[0].host === '127.0.0.1')
assert('every candidate explains itself', candidates.every((c) => c.why.length > 0))
// Docker may or may not exist here; either way these must resolve, not throw.
assert('docker gateway lookup degrades gracefully', (await dockerGateway()) !== undefined)
assert('container lookup degrades gracefully', (await dockerContainerIp('fulcrum')) !== undefined)

// --- the failure message has to be actionable -------------------------------
const remedy = remedyFor('indexer')
assert('remedy names the docker network', remedy.includes('dojonet'))
assert('remedy offers publishing the port', remedy.includes('publish the port'))
assert('remedy offers running as a container', remedy.includes('container attached'))
assert('remedy names the env override', remedy.includes('PAYNYM_BOT_ELECTRUM_HOST'))
assert('soroban remedy names its own override', remedyFor('soroban').includes('PAYNYM_BOT_SOROBAN'))

electrum.close()
mute.close()
soroban.close()

console.log('')
if (failures === 0) {
  console.log('PASS — Dojo service discovery, proven by protocol not by open ports.')
} else {
  console.log(`FAIL — ${failures} discovery check(s) failed.`)
  process.exit(1)
}
