// The used-address oracle, against a fake Electrum server.
//
// This is the piece that lets the bot notice a payment at all, so it is worth
// exercising the unhappy paths: a server that errors, one that never answers,
// and one that drops the connection mid-life.

import { createServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { sha256 } from '@noble/hashes/sha256'
import { base58check as base58checkFactory } from '@scure/base'
import { MAINNET, TESTNET } from '../src/bip47.ts'
import { ElectrumClient, addressToScriptHash, electrumUsedChecker } from '../src/electrum.ts'

const base58check = base58checkFactory(sha256)

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

// Bob's receive[0] from the official BIP47 vectors.
const ADDR = '141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK'

// --- script hash derivation -------------------------------------------------
// Recomputed here from the documented steps, independently of the
// implementation, so a transcription slip in either shows up as a mismatch.
function scriptHashByHand(address: string): string {
  const payload = base58check.decode(address)
  const script = Uint8Array.from([0x76, 0xa9, 0x14, ...payload.subarray(1), 0x88, 0xac])
  return Buffer.from(sha256(script)).reverse().toString('hex')
}

assert('script hash matches an independent computation',
  addressToScriptHash(ADDR, MAINNET) === scriptHashByHand(ADDR))
assert('script hash is pinned',
  addressToScriptHash(ADDR, MAINNET) ===
    'a4fddfe5153ae3b1826ca5e78aeb6fc54f09c1b9708a9f028b49946a32f65473')

try {
  addressToScriptHash(ADDR, TESTNET)
  assert('a mainnet address is refused on testnet', false)
} catch (e) {
  assert('a mainnet address is refused on testnet',
    (e as Error).message.includes('not on the configured network'))
}

// --- fake Electrum server ---------------------------------------------------
type Behaviour = 'used' | 'unused' | 'error' | 'silent' | 'drop'
let behaviour: Behaviour = 'unused'
let sawScriptHash: string | null = null

const server = createServer((socket) => {
  let buf = ''
  socket.setEncoding('utf8')
  socket.on('error', () => {}) // client-side destroys are expected here
  socket.on('data', (chunk: string) => {
    buf += chunk
    let nl: number
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl)
      buf = buf.slice(nl + 1)
      const req = JSON.parse(line)

      if (behaviour === 'silent') continue
      if (behaviour === 'drop') { socket.destroy(); return }

      let body: Record<string, unknown>
      if (req.method === 'server.version') {
        body = { id: req.id, result: ['Fulcrum 1.9.1', '1.4'] }
      } else if (behaviour === 'error') {
        body = { id: req.id, error: { message: 'invalid scripthash' } }
      } else {
        sawScriptHash = req.params[0]
        body = { id: req.id, result: behaviour === 'used' ? [{ tx_hash: 'ab', height: 800000 }] : [] }
      }
      socket.write(`${JSON.stringify(body)}\n`)
    }
  })
})
await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
const { port } = server.address() as AddressInfo

const client = new ElectrumClient({ host: '127.0.0.1', port, timeoutMs: 700 })

// --- happy paths ------------------------------------------------------------
assert('server.version round-trips', Array.isArray(await client.serverVersion()))

behaviour = 'unused'
assert('an unseen address is not used', (await client.isUsed(ADDR, MAINNET)) === false)
assert('the query used the right script hash', sawScriptHash === addressToScriptHash(ADDR, MAINNET))

behaviour = 'used'
assert('a paid address is used', (await client.isUsed(ADDR, MAINNET)) === true)

// A mempool-only entry still counts: the merchant wants to know immediately.
assert('the oracle adapter works', (await electrumUsedChecker(client, MAINNET)(ADDR)) === true)

// --- unhappy paths ----------------------------------------------------------
behaviour = 'error'
await rejects('a server error rejects', () => client.isUsed(ADDR, MAINNET), 'invalid scripthash')

behaviour = 'silent'
await rejects('a silent server times out', () => client.isUsed(ADDR, MAINNET), 'timed out')

// A dropped connection must fail the in-flight call rather than hang it...
behaviour = 'drop'
await rejects('a dropped connection rejects', () => client.isUsed(ADDR, MAINNET))

// ...and the next call must transparently reconnect.
behaviour = 'used'
assert('the client reconnects after a drop', (await client.isUsed(ADDR, MAINNET)) === true)

client.close()

// A refused connection is an error, not a hang.
const dead = new ElectrumClient({ host: '127.0.0.1', port: 1, timeoutMs: 700 })
await rejects('an unreachable indexer rejects', () => dead.isUsed(ADDR, MAINNET))
dead.close()

await new Promise<void>((r) => server.close(() => r()))

console.log('')
if (failures === 0) {
  console.log('PASS — used-address oracle over the Electrum protocol.')
} else {
  console.log(`FAIL — ${failures} electrum check(s) failed.`)
  process.exit(1)
}
