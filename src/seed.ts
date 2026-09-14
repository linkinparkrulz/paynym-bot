// The merchant's wallet seed.
//
// A BIP39 mnemonic, not raw hex. The operator has to be able to hold this: raw
// master-seed hex cannot be imported by any wallet, and has no checksum, so a
// single mistyped character out of 128 silently yields a valid but DIFFERENT
// wallet. Twelve words is what Samourai and Ashigaru generate, so it is what an
// operator will expect — but import accepts any valid BIP39 length, since
// someone bringing an existing PayNym may well have 24.
//
// About the passphrase: on an always-online box it buys no security, because it
// necessarily sits beside the mnemonic. It is supported purely for
// COMPATIBILITY — if the PayNym being imported was created with one, omitting it
// derives a different wallet — and the CLI says so rather than implying it is a
// second factor.
//
// A seed backup is NOT a complete backup. A BIP47 receive address is a function
// of BOTH parties' payment codes, so without the registered customer codes in
// state.json, money already received cannot be found. See ./state.ts.

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'

/** 128 bits of entropy -> 12 words, matching Samourai/Ashigaru. */
export const DEFAULT_STRENGTH_BITS = 128

export function newMnemonic(strengthBits = DEFAULT_STRENGTH_BITS): string {
  return generateMnemonic(wordlist, strengthBits)
}

/** True if `phrase` is a well-formed BIP39 mnemonic with a valid checksum. */
export function isValidMnemonic(phrase: string): boolean {
  try {
    return validateMnemonic(normaliseMnemonic(phrase), wordlist)
  } catch {
    return false
  }
}

/** Collapse whitespace and lowercase; BIP39 words are lowercase ASCII. */
export function normaliseMnemonic(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).join(' ')
}

/** The 64-byte BIP32 master seed for a mnemonic (and optional passphrase). */
export function seedFromMnemonic(phrase: string, passphrase = ''): Uint8Array {
  const mnemonic = normaliseMnemonic(phrase)
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error(
      'invalid mnemonic: the checksum does not match. Check for a mistyped or ' +
        'out-of-order word — BIP39 catches this, which is exactly why we use it.',
    )
  }
  return mnemonicToSeedSync(mnemonic, passphrase)
}

export type SeedFile = {
  /** Present when the file holds a mnemonic; absent for a legacy hex seed. */
  mnemonic?: string
  passphrase?: string
  seed: Uint8Array
}

const HEX_SEED = /^[0-9a-f]+$/i

/**
 * Read a seed file, accepting either a BIP39 mnemonic or a legacy raw-hex master
 * seed. Deployments created before mnemonics existed must keep working: changing
 * how their seed is read would change their PayNym, orphaning every customer.
 */
export function readSeedFile(path: string, passphrase = ''): SeedFile {
  if (!existsSync(path)) {
    throw new Error(`no seed at ${path} — run "paynym-bot init" first`)
  }
  const raw = readFileSync(path, 'utf8').trim()

  if (HEX_SEED.test(raw) && raw.length % 2 === 0 && raw.length >= 32) {
    // Legacy: raw BIP32 master seed as hex.
    return { seed: Uint8Array.from(Buffer.from(raw, 'hex')) }
  }

  const mnemonic = normaliseMnemonic(raw)
  if (!isValidMnemonic(mnemonic)) {
    throw new Error(
      `seed at ${path} is neither a valid BIP39 mnemonic nor a hex master seed`,
    )
  }
  return { mnemonic, passphrase, seed: seedFromMnemonic(mnemonic, passphrase) }
}

/** Write a mnemonic owner-only. Never widen these permissions. */
export function writeMnemonicFile(path: string, mnemonic: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  writeFileSync(path, `${normaliseMnemonic(mnemonic)}\n`, { mode: 0o600 })
  chmodSync(path, 0o600)
}
