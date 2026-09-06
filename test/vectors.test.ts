// The gate. Official BIP47 test vectors (Alice & Bob). Nothing downstream is
// worth trusting unless this prints PASS. Run: npm run vectors
//
// Vectors sourced from the BIP47 specification's reference test vectors.

import { HDKey } from '@scure/bip32'
import {
  MAINNET,
  TESTNET,
  encodePaymentCode,
  decodePaymentCode,
  p2pkhAddress,
  receiveAddress,
  sendAddress,
} from '../src/bip47.ts'

const ALICE_SEED =
  '64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a'
const BOB_SEED =
  '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110'

const ALICE_PC =
  'PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA'
const BOB_PC =
  'PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97'
const BOB_NOTIFICATION = '1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV'

// Bob's receiving addresses for payments from Alice, indexes 0..9.
const BOB_RECEIVE = [
  '141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK',
  '12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6',
  '1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc',
  '1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA',
  '1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL',
  '1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t',
  '1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD',
  '16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e',
  '17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5',
  '1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s',
]

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'))

let failures = 0
function check(name: string, got: unknown, want: unknown): void {
  const ok = got === want
  if (!ok) failures++
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}`)
  if (!ok) console.log(`        got:  ${got}\n        want: ${want}`)
}

const aliceAccount = HDKey.fromMasterSeed(fromHex(ALICE_SEED)).derive("m/47'/0'/0'")
const bobAccount = HDKey.fromMasterSeed(fromHex(BOB_SEED)).derive("m/47'/0'/0'")

// 1. Payment code encoding.
check('alice payment code', encodePaymentCode(aliceAccount.publicKey!, aliceAccount.chainCode!), ALICE_PC)
check('bob payment code', encodePaymentCode(bobAccount.publicKey!, bobAccount.chainCode!), BOB_PC)

// 2. Payment code decode round-trips to the account pubkey.
check('alice pc decode', Buffer.from(decodePaymentCode(ALICE_PC).pubkey).toString('hex'), Buffer.from(aliceAccount.publicKey!).toString('hex'))

// 3. Bob's notification address = P2PKH(account child 0).
check('bob notification address', p2pkhAddress(bobAccount.deriveChild(0).publicKey!, MAINNET), BOB_NOTIFICATION)

// 4. Bob's receive addresses, derived from Alice's payment code only (his side).
for (let i = 0; i < BOB_RECEIVE.length; i++) {
  check(`bob receive[${i}] (receiver side)`, receiveAddress(bobAccount, ALICE_PC, i), BOB_RECEIVE[i])
}

// 5. Alice's send addresses, derived from Bob's payment code only (her side),
//    must equal Bob's receive addresses. This equality is the whole mechanism:
//    both parties compute the same address from just the two payment codes, with
//    no notification transaction between them.
for (let i = 0; i < BOB_RECEIVE.length; i++) {
  check(`alice send[${i}] == bob receive[${i}]`, sendAddress(aliceAccount, BOB_PC, i), BOB_RECEIVE[i])
}

// 6. Testnet. A payment code carries no network information, so the derivation
//    itself must be network-independent; the network may only reach the final
//    address encoding. Regression for a synthetic-xpub version byte that made
//    every testnet derivation throw 'Version mismatch', leaving the README's own
//    "testnet first" instruction unrunnable.
const aliceTestnet = HDKey.fromMasterSeed(fromHex(ALICE_SEED)).derive("m/47'/1'/0'")
const bobTestnet = HDKey.fromMasterSeed(fromHex(BOB_SEED)).derive("m/47'/1'/0'")
const aliceTestnetPC = encodePaymentCode(aliceTestnet.publicKey!, aliceTestnet.chainCode!)
const bobTestnetPC = encodePaymentCode(bobTestnet.publicKey!, bobTestnet.chainCode!)

for (let i = 0; i < 10; i++) {
  const recv = receiveAddress(bobTestnet, aliceTestnetPC, i, TESTNET)
  check(`testnet alice send[${i}] == bob receive[${i}]`, sendAddress(aliceTestnet, bobTestnetPC, i, TESTNET), recv)
  check(`testnet receive[${i}] encodes as testnet`, recv[0] === 'm' || recv[0] === 'n', true)
}

// The network must still reach the address encoding: same keys, different net,
// different address. Guards against "fixing" testnet by ignoring the network.
check(
  'testnet and mainnet addresses differ',
  receiveAddress(bobTestnet, aliceTestnetPC, 0, TESTNET) !==
    receiveAddress(bobTestnet, aliceTestnetPC, 0, MAINNET),
  true,
)

console.log('')
if (failures === 0) {
  console.log('PASS — all BIP47 vectors reproduced from payment codes alone.')
} else {
  console.log(`FAIL — ${failures} vector check(s) failed.`)
  process.exit(1)
}
