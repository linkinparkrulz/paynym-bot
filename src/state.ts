// Durable daemon state.
//
// This file is the other half of the backup, alongside the seed. Receive keys
// CANNOT be re-derived from the seed alone: a BIP47 address is a function of
// BOTH parties' payment codes, so the registered customer codes kept here are
// required to find money that has already arrived. Losing this file does not
// lose funds outright, but it makes them undiscoverable until every customer
// registers again.
//
// The network is recorded here and is immutable for the life of the state. It
// fixes the BIP47 derivation path (m/47'/0' vs m/47'/1') and therefore the
// merchant's own payment code, so running against a different network would
// silently present a different PayNym and orphan every registered customer.

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { MAINNET, TESTNET } from './bip47.ts'
import type { Network } from './bip47.ts'
import type { SenderRecord } from './register.ts'

export const STATE_VERSION = 1

export type NetworkName = 'mainnet' | 'testnet'

const NETWORKS: Record<NetworkName, Network> = { mainnet: MAINNET, testnet: TESTNET }

export function isNetworkName(value: unknown): value is NetworkName {
  return value === 'mainnet' || value === 'testnet'
}

/** The Network parameters for a stored network name. */
export function networkFor(name: NetworkName): Network {
  return NETWORKS[name]
}

export type PersistedState = {
  version: number
  /** Chosen at init and never changed. See the note at the top of this file. */
  network: NetworkName
  createdAt: number
  /** Optional shop name shown on the storefront above the payment code. */
  label?: string
  /** Customers who have registered with us. Required to derive receive keys. */
  senders: SenderRecord[]
}

export function newState(
  network: NetworkName,
  now = Date.now(),
  label?: string,
): PersistedState {
  return { version: STATE_VERSION, network, createdAt: now, label, senders: [] }
}

/** Parse and validate raw state JSON. Throws with an actionable message. */
export function parseState(raw: string): PersistedState {
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    throw new Error('state file is not valid JSON; restore it from your backup')
  }
  const s = value as Partial<PersistedState>
  if (s.version !== STATE_VERSION) {
    throw new Error(`unsupported state version ${String(s.version)} (expected ${STATE_VERSION})`)
  }
  if (!isNetworkName(s.network)) {
    throw new Error(`state file has an invalid network: ${String(s.network)}`)
  }
  if (!Array.isArray(s.senders)) throw new Error('state file has no senders array')
  return {
    version: STATE_VERSION,
    network: s.network,
    createdAt: typeof s.createdAt === 'number' ? s.createdAt : 0,
    label: typeof s.label === 'string' ? s.label : undefined,
    senders: s.senders as SenderRecord[],
  }
}

export function loadState(path: string): PersistedState {
  if (!existsSync(path)) throw new Error(`no state at ${path} — run "paynym-bot init" first`)
  return parseState(readFileSync(path, 'utf8'))
}

/**
 * Write state atomically: a full write to a temp file in the same directory,
 * then a rename. A crash mid-write can therefore never leave a truncated state
 * file, which would take the customer payment codes with it.
 */
export function saveState(path: string, state: PersistedState): void {
  mkdirSync(dirname(path), { recursive: true })
  const tmp = `${path}.tmp`
  writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
  renameSync(tmp, path)
  chmodSync(path, 0o600)
}

/**
 * Refuse to run against a network other than the one this state was created
 * with. Loud failure beats silently presenting a different PayNym.
 */
export function assertNetworkMatches(state: PersistedState, configured: NetworkName): void {
  if (state.network !== configured) {
    throw new Error(
      `network mismatch: this state was created for ${state.network}, but ${configured} was ` +
        `requested. The network fixes the BIP47 derivation path and therefore the PayNym ` +
        `itself, so it cannot be changed. Use --network ${state.network}, or run init in a ` +
        `separate data directory to operate on ${configured}.`,
    )
  }
}
