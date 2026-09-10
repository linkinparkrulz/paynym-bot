// State, network locking, and the init-time network choice.
//
// The network is chosen once at init and recorded in the state file. It fixes
// the BIP47 derivation path and therefore the merchant's own payment code, so
// running the same seed against a different network is a DIFFERENT receiver.
// These tests pin that: the choice takes effect, and a mismatch is refused
// loudly rather than silently presenting another PayNym.

import { mkdtempSync, existsSync, statSync, rmSync, writeFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PaynymIdentity } from '../src/identity.ts'
import {
  STATE_VERSION,
  assertNetworkMatches,
  isNetworkName,
  loadState,
  networkFor,
  newState,
  parseState,
  saveState,
} from '../src/state.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}
function throws(name: string, fn: () => unknown, expect?: string): void {
  try {
    fn()
    assert(name, false)
  } catch (e) {
    const msg = (e as Error).message
    assert(name, expect ? msg.includes(expect) : true)
  }
}

const dir = mkdtempSync(join(tmpdir(), 'paynym-state-'))

// --- network name guard -----------------------------------------------------
assert('isNetworkName accepts mainnet', isNetworkName('mainnet'))
assert('isNetworkName accepts testnet', isNetworkName('testnet'))
assert('isNetworkName rejects regtest', !isNetworkName('regtest'))
assert('isNetworkName rejects undefined', !isNetworkName(undefined))

// --- parse validation -------------------------------------------------------
throws('parseState rejects non-JSON', () => parseState('{not json'), 'not valid JSON')
throws(
  'parseState rejects a future version',
  () => parseState(JSON.stringify({ version: 99, network: 'testnet', senders: [] })),
  'unsupported state version',
)
throws(
  'parseState rejects an unknown network',
  () => parseState(JSON.stringify({ version: STATE_VERSION, network: 'regtest', senders: [] })),
  'invalid network',
)
throws(
  'parseState rejects missing senders',
  () => parseState(JSON.stringify({ version: STATE_VERSION, network: 'testnet' })),
  'no senders array',
)

// --- round trip and atomic write -------------------------------------------
const statePath = join(dir, 'state.json')
const state = newState('testnet', 1234)
state.senders.push({ paymentCode: 'PM8TEST', firstSeen: 1, nextIndex: 0 })
saveState(statePath, state)

const reloaded = loadState(statePath)
assert('state round-trips the network', reloaded.network === 'testnet')
assert('state round-trips senders', reloaded.senders.length === 1)
assert('state round-trips createdAt', reloaded.createdAt === 1234)
assert('no temp file is left behind', !existsSync(`${statePath}.tmp`))
assert('state file is owner-only', (statSync(statePath).mode & 0o077) === 0)

throws(
  'loadState explains a missing file',
  () => loadState(join(dir, 'absent.json')),
  'run "paynym-bot init"',
)

// --- the network lock -------------------------------------------------------
assertNetworkMatches(reloaded, 'testnet')
assert('matching network is accepted', true)
throws(
  'mismatched network is refused',
  () => assertNetworkMatches(reloaded, 'mainnet'),
  'network mismatch',
)
throws(
  'the refusal names the stored network',
  () => assertNetworkMatches(reloaded, 'mainnet'),
  'created for testnet',
)

// --- the choice actually changes the receiver -------------------------------
// Same seed, different network: different derivation path, different PayNym.
// This is why the choice cannot be revisited after customers register.
const seed = Uint8Array.from(Buffer.from('11'.repeat(64), 'hex'))
const onTestnet = PaynymIdentity.fromSeed(seed, networkFor('testnet'))
const onMainnet = PaynymIdentity.fromSeed(seed, networkFor('mainnet'))

assert('same seed yields a different PayNym per network', onTestnet.paymentCode() !== onMainnet.paymentCode())
const tAddr = onTestnet.notificationAddress()
const mAddr = onMainnet.notificationAddress()
assert('testnet identity encodes testnet addresses', tAddr[0] === 'm' || tAddr[0] === 'n')
assert('mainnet identity encodes mainnet addresses', mAddr[0] === '1')

// A testnet receiver's watch addresses are testnet too, all the way through.
const peer = PaynymIdentity.fromSeed(
  Uint8Array.from(Buffer.from('22'.repeat(64), 'hex')),
  networkFor('testnet'),
)
const recv = onTestnet.receiveAddress(peer.paymentCode(), 0)
assert('testnet receive address encodes testnet', recv[0] === 'm' || recv[0] === 'n')
assert(
  'testnet sender agrees on the address',
  peer.sendAddress(onTestnet.paymentCode(), 0) === recv,
)

// --- the published host survives a round trip -------------------------------
// The auth47 flow is bound to this value and refuses to serve without it, so
// it has to persist across restarts like any other deployment parameter.
{
  const onionPath = join(dir, 'onion-state.json')
  saveState(onionPath, { ...newState('mainnet'), onion: 'shop7charactersonionaddress.onion' })
  assert('the onion round-trips through the state file',
    loadState(onionPath).onion === 'shop7charactersonionaddress.onion')

  const bare = join(dir, 'bare-state.json')
  saveState(bare, newState('mainnet'))
  assert('an absent onion reads back as undefined', loadState(bare).onion === undefined)

  // An empty string must not read back as a configured host: it would satisfy
  // a truthiness check somewhere and re-enable the flow with no binding.
  const empty = join(dir, 'empty-state.json')
  writeFileSync(empty, JSON.stringify({ ...newState('mainnet'), onion: '' }))
  assert('an empty onion is treated as unset', loadState(empty).onion === undefined)
}

// --- an unreadable state file says what to do about it ----------------------
// The file is 0600 and owned by the service account, and the CLI is on the
// operator's PATH, so "exists but unreadable" is routine. An EACCES stack is a
// poor way to learn that sudo was needed. Skipped as root, which can read it.
if (process.getuid?.() !== 0) {
  const locked = join(dir, 'locked-state.json')
  saveState(locked, newState('mainnet'))
  chmodSync(locked, 0o000)
  let message = ''
  try {
    loadState(locked)
  } catch (err) {
    message = (err as Error).message
  }
  chmodSync(locked, 0o600) // so the cleanup below can remove it
  assert('an unreadable state file is not reported as missing', !/no state at/.test(message))
  assert('the error names sudo as the fix', /sudo/.test(message))
  assert('and names --data as the alternative', /--data/.test(message))
}

rmSync(dir, { recursive: true, force: true })

console.log('')
if (failures === 0) {
  console.log('PASS — state, network lock, and init-time network choice.')
} else {
  console.log(`FAIL — ${failures} state check(s) failed.`)
  process.exit(1)
}
