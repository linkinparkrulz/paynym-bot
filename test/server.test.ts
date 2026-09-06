// Storefront behaviour, and above all what it does NOT expose.
//
// This server sits behind the onion and is readable by anyone with the
// address. The payment code and network are meant to be public. The registered
// customer payment codes are not: that set is the merchant's counterparty
// graph, and even its SIZE is their trading volume. These tests pin that
// boundary so a later change cannot quietly widen it.

import { PaynymIdentity } from '../src/identity.ts'
import { createStorefront } from '../src/server.ts'
import { networkFor } from '../src/state.ts'
import type { AddressInfo } from 'node:net'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const seed = Uint8Array.from(Buffer.from('33'.repeat(64), 'hex'))
const identity = PaynymIdentity.fromSeed(seed, networkFor('testnet'))
const customer = PaynymIdentity.fromSeed(
  Uint8Array.from(Buffer.from('44'.repeat(64), 'hex')),
  networkFor('testnet'),
)

const server = createStorefront({ identity, network: 'testnet', label: 'Test Shop' })
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
const { port } = server.address() as AddressInfo
const base = `http://127.0.0.1:${port}`

// --- public status ----------------------------------------------------------
const statusRes = await fetch(`${base}/api/status`)
const status = await statusRes.json()
assert('status responds 200', statusRes.status === 200)
assert('status exposes the payment code', status.paymentCode === identity.paymentCode())
assert('status exposes the network', status.network === 'testnet')
assert('status exposes the label', status.label === 'Test Shop')
assert('status is not cached', statusRes.headers.get('cache-control') === 'no-store')

// --- the privacy boundary ---------------------------------------------------
// Serialise the whole response and assert nothing customer-shaped is in it.
const raw = JSON.stringify(status)
assert('status does not leak a customer payment code', !raw.includes(customer.paymentCode()))
assert('status has no senders field', !('senders' in status))
assert('status has no watch list', !('watch' in status) && !('addresses' in status))
assert(
  'status discloses no customer count under any key',
  !Object.keys(status).some((k) => /sender|customer|count|registered|watch/i.test(k)),
)

// --- the page ---------------------------------------------------------------
const pageRes = await fetch(`${base}/`)
const page = await pageRes.text()
assert('page responds 200', pageRes.status === 200)
assert('page is html', (pageRes.headers.get('content-type') ?? '').startsWith('text/html'))
assert('page sets a content security policy', pageRes.headers.get('content-security-policy') !== null)
assert('page sends no referrer', pageRes.headers.get('referrer-policy') === 'no-referrer')
// Onion-only: the page must not pull anything from the clearnet.
assert('page loads no external resources', !/https?:\/\/(?!127\.0\.0\.1)/i.test(page))
assert('page does not inline the payment code', !page.includes(identity.paymentCode()))

// --- everything else --------------------------------------------------------
assert('health check responds', (await fetch(`${base}/healthz`)).status === 200)
assert('unknown paths 404', (await fetch(`${base}/../secrets`)).status === 404)
assert(
  'writes are rejected',
  (await fetch(`${base}/`, { method: 'POST' })).status === 405,
)

await new Promise<void>((resolve) => server.close(() => resolve()))

console.log('')
if (failures === 0) {
  console.log('PASS — storefront serves the PayNym and leaks nothing else.')
} else {
  console.log(`FAIL — ${failures} storefront check(s) failed.`)
  process.exit(1)
}
