// Endpoint parsing, and the rule that stops a mainnet deployment handing its
// customer list to a stranger.

import {
  assertIndexerAllowed,
  isLocalHost,
  isOnion,
  normaliseSorobanUrl,
  parseElectrumEndpoint,
} from '../src/config.ts'

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
    assert(name, expect ? (e as Error).message.includes(expect) : true)
  }
}

const ONION = '2jf3kuf4xuejufgbmd3bmyoifpwrp3fhlm46ohptc5w2arx6aur5shid.onion'
const SOROBAN_ONION = 'jfvhxw2xziznrthfhxnk45e7whvkb2gwmzh3ejqblcrbx4ah6ijo27yd.onion'

// --- the exact form Dojo Bay prints -----------------------------------------
const dojobay = parseElectrumEndpoint(`tcp://${ONION}:50001`)
assert('parses tcp:// as Dojo Bay prints it', dojobay.host === ONION && dojobay.port === 50001)
assert('host:port without a scheme', parseElectrumEndpoint('127.0.0.1:50001').port === 50001)
assert('a bare host defaults to the electrum port', parseElectrumEndpoint(ONION).port === 50001)
assert('a trailing slash is tolerated', parseElectrumEndpoint(`tcp://${ONION}:50001/`).port === 50001)
throws('an empty endpoint is refused', () => parseElectrumEndpoint('  '), 'empty')
throws('a non-numeric port is refused', () => parseElectrumEndpoint('host:abc'), 'invalid indexer port')
throws('an out-of-range port is refused', () => parseElectrumEndpoint('host:99999'), 'invalid indexer port')

// --- soroban, listed bare -----------------------------------------------------
assert('a bare onion becomes an rpc url',
  normaliseSorobanUrl(SOROBAN_ONION) === `http://${SOROBAN_ONION}/rpc`)
assert('an explicit path is respected',
  normaliseSorobanUrl(`http://${SOROBAN_ONION}/other`) === `http://${SOROBAN_ONION}/other`)
assert('a local url with a port survives',
  normaliseSorobanUrl('http://127.0.0.1:4242/rpc') === 'http://127.0.0.1:4242/rpc')
assert('a scheme-less host:port gets /rpc',
  normaliseSorobanUrl('127.0.0.1:4242') === 'http://127.0.0.1:4242/rpc')
throws('an empty soroban endpoint is refused', () => normaliseSorobanUrl(''), 'empty')

// --- classification ----------------------------------------------------------
assert('detects an onion', isOnion(ONION))
assert('does not mistake a normal host for an onion', !isOnion('example.com'))
assert('loopback is local', isLocalHost('127.0.0.1') && isLocalHost('localhost'))
assert('dojonet (172.29.x) is local', isLocalHost('172.29.1.3'))
assert('other RFC1918 is local', isLocalHost('10.0.0.5') && isLocalHost('192.168.1.9'))
assert('172.32.x is NOT private', !isLocalHost('172.32.0.1'))
assert('an onion is not local', !isLocalHost(ONION))
assert('a public address is not local', !isLocalHost('8.8.8.8'))

// --- the guard ----------------------------------------------------------------
// Testnet is where a remote indexer is legitimate: nothing real to leak.
assertIndexerAllowed('testnet', ONION, false)
assert('testnet may use a remote indexer', true)
assertIndexerAllowed('mainnet', '127.0.0.1', false)
assert('mainnet may use its own indexer', true)
assertIndexerAllowed('mainnet', '172.29.1.3', false)
assert('mainnet may use a dojonet indexer', true)

throws('mainnet refuses a remote indexer', () => assertIndexerAllowed('mainnet', ONION, false),
  'refusing to run mainnet')
throws('the refusal explains what leaks', () => assertIndexerAllowed('mainnet', ONION, false),
  'your entire customer list')
throws('the refusal names the override', () => assertIndexerAllowed('mainnet', ONION, false),
  'PAYNYM_BOT_ALLOW_REMOTE_INDEXER')
throws('a public indexer is refused too', () => assertIndexerAllowed('mainnet', '8.8.8.8', false),
  'refusing to run mainnet')

assertIndexerAllowed('mainnet', ONION, true)
assert('an explicit override is honoured', true)

console.log('')
if (failures === 0) {
  console.log('PASS — endpoint parsing, and the mainnet remote-indexer guard.')
} else {
  console.log(`FAIL — ${failures} config check(s) failed.`)
  process.exit(1)
}
