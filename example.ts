// One-shot live demo against a real Soroban node: a customer registers with an
// always-online merchant, with no notification transaction, and both sides
// agree on the address to pay.
//
// Usage:
//   node --experimental-strip-types example.ts --soroban http://127.0.0.1:4242/rpc
//
// In a real deployment Soroban sits beside the bot on the Dojo host, so this
// talks to loopback and needs no SOCKS client. For the daemon proper, use the
// CLI instead: `paynym-bot init` then `paynym-bot serve`.

import { parseArgs } from 'node:util'
import { randomBytes } from 'node:crypto'
import { PaynymIdentity } from './src/identity.ts'
import { SorobanRPC } from './src/soroban.ts'
import { Registrar, Registry, registerWithReceiver } from './src/register.ts'
import { watchWindow } from './src/watcher.ts'

const { values } = parseArgs({ options: { soroban: { type: 'string', short: 's' } } })
const url = values.soroban
if (!url) {
  console.error('pass --soroban http://<node>/rpc')
  process.exit(1)
}

const rpc = SorobanRPC.forUrl(url)

// Fresh identities for the demo. In production the merchant's seed is fixed and
// backed up alongside its state file.
const merchant = PaynymIdentity.fromSeed(randomBytes(64))
const customer = PaynymIdentity.fromSeed(randomBytes(64))

const registrar = new Registrar(merchant, new Registry())

console.log('merchant payment code:', merchant.paymentCode())
console.log('inbox directory:      ', registrar.inbox())

// The customer needs nothing but the payment code from the merchant's page.
console.log('\ncustomer registering (no notification tx)...')
await registerWithReceiver(rpc, customer, merchant.paymentCode())

console.log('merchant draining inbox...')
const added = await registrar.poll(rpc)
console.log('newly registered customers:', added.length)

for (const w of watchWindow(merchant, registrar.registry)) {
  const agrees = customer.sendAddress(merchant.paymentCode(), w.index) === w.address
  console.log(`  watch[${w.index}] ${w.address}  customer-agrees=${agrees}`)
}
