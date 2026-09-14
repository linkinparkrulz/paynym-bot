// The wallet seed: BIP39 mnemonics, and compatibility with what came before.
//
// Two things must hold or an operator loses access to money:
//   * a mnemonic must derive the seed BIP39 says it does, so the phrase works in
//     any other wallet;
//   * an existing raw-hex seed file must keep deriving the SAME PayNym, or
//     upgrading silently becomes a different merchant and orphans every
//     registered customer.

import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PaynymIdentity } from '../src/identity.ts'
import { networkFor } from '../src/state.ts'
import {
  isValidMnemonic,
  newMnemonic,
  normaliseMnemonic,
  readSeedFile,
  seedFromMnemonic,
  writeMnemonicFile,
} from '../src/seed.ts'

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

const hex = (u8: Uint8Array) => Buffer.from(u8).toString('hex')
const dir = mkdtempSync(join(tmpdir(), 'paynym-seed-'))

// --- generation -------------------------------------------------------------
const fresh = newMnemonic()
assert('generates 12 words', fresh.split(' ').length === 12)
assert('a generated mnemonic validates', isValidMnemonic(fresh))
assert('two generations differ', newMnemonic() !== newMnemonic())

// --- BIP39 conformance ------------------------------------------------------
// The canonical all-"abandon" vector. If these match, the phrase means the same
// thing here as it does in any other BIP39 wallet.
const VECTOR = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
assert('matches the BIP39 vector seed (no passphrase)',
  hex(seedFromMnemonic(VECTOR)) ===
    '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1' +
    '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
assert('matches the BIP39 vector seed (passphrase TREZOR)',
  hex(seedFromMnemonic(VECTOR, 'TREZOR')) ===
    'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553' +
    '1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04')
assert('a seed is 64 bytes', seedFromMnemonic(VECTOR).length === 64)

// --- checksum and normalisation --------------------------------------------
const badChecksum = VECTOR.replace(/about$/, 'abandon')
assert('a bad checksum is invalid', !isValidMnemonic(badChecksum))
throws('a bad checksum throws on use', () => seedFromMnemonic(badChecksum), 'checksum does not match')
assert('an unknown word is invalid', !isValidMnemonic(VECTOR.replace('about', 'zzzz')))
assert('normalises case and whitespace',
  normaliseMnemonic('  ABANDON   abandon\tABOUT ') === 'abandon abandon about')
assert('a messy but valid phrase still works',
  hex(seedFromMnemonic(`  ${VECTOR.toUpperCase().replace(/ /g, '   ')}  `)) ===
    hex(seedFromMnemonic(VECTOR)))

// --- the passphrase is a different wallet, not a second factor --------------
const plain = PaynymIdentity.fromSeed(seedFromMnemonic(VECTOR), networkFor('mainnet'))
const passed = PaynymIdentity.fromSeed(seedFromMnemonic(VECTOR, 'TREZOR'), networkFor('mainnet'))
assert('a passphrase yields a different PayNym', plain.paymentCode() !== passed.paymentCode())

// --- import is deterministic ------------------------------------------------
assert('the same phrase always gives the same PayNym',
  PaynymIdentity.fromSeed(seedFromMnemonic(VECTOR), networkFor('mainnet')).paymentCode() ===
    plain.paymentCode())

// --- files ------------------------------------------------------------------
const mnemonicPath = join(dir, 'seed')
writeMnemonicFile(mnemonicPath, `  ${VECTOR.toUpperCase()}  `)
assert('a written mnemonic is owner-only', (statSync(mnemonicPath).mode & 0o077) === 0)

const loaded = readSeedFile(mnemonicPath)
assert('a mnemonic file round-trips normalised', loaded.mnemonic === VECTOR)
assert('a mnemonic file yields the right seed', hex(loaded.seed) === hex(seedFromMnemonic(VECTOR)))
assert('a passphrase is applied on read',
  hex(readSeedFile(mnemonicPath, 'TREZOR').seed) === hex(seedFromMnemonic(VECTOR, 'TREZOR')))

// Legacy raw-hex seed: an existing deployment must keep its identity exactly.
const legacyPath = join(dir, 'legacy-seed')
const legacyHex = '11'.repeat(64)
writeFileSync(legacyPath, `${legacyHex}\n`)
const legacy = readSeedFile(legacyPath)
assert('a legacy hex seed still loads', hex(legacy.seed) === legacyHex)
assert('a legacy seed reports no mnemonic', legacy.mnemonic === undefined)
assert('a legacy seed derives the unchanged PayNym',
  PaynymIdentity.fromSeed(legacy.seed, networkFor('mainnet')).paymentCode() ===
    PaynymIdentity.fromSeed(
      Uint8Array.from(Buffer.from(legacyHex, 'hex')),
      networkFor('mainnet'),
    ).paymentCode())

const junkPath = join(dir, 'junk-seed')
writeFileSync(junkPath, 'not a mnemonic and not hex\n')
throws('garbage is rejected', () => readSeedFile(junkPath), 'neither a valid BIP39 mnemonic')
throws('a missing seed explains itself', () => readSeedFile(join(dir, 'nope')), 'paynym-bot init')

rmSync(dir, { recursive: true, force: true })

console.log('')
if (failures === 0) {
  console.log('PASS — BIP39 mnemonics, and legacy seeds keep their identity.')
} else {
  console.log(`FAIL — ${failures} seed check(s) failed.`)
  process.exit(1)
}
