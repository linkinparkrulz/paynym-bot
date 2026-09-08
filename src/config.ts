// Runtime configuration: where state lives and what services to talk to.
//
// Two deployment shapes are supported, and they can be mixed per endpoint:
//
//   local  — a Dojo on the same host. Everything is reached over loopback or
//            the dojonet bridge, so no Tor client is involved; Tor is only
//            configuration for the hidden service the bot EXPOSES.
//   onion  — a remote Dojo published as hidden services, as Dojo Bay lists
//            them. Reached through Tor's SOCKS proxy (see ./socks.ts).
//
// The mixed case is real: a remote testnet indexer with a local Soroban is how
// an operator whose only Dojo is mainnet can rehearse on testnet at all.

import { homedir } from 'node:os'
import { join } from 'node:path'
import { DEFAULT_TOR_SOCKS_HOST, DEFAULT_TOR_SOCKS_PORT } from './socks.ts'
import type { SocksProxy } from './socks.ts'
import type { NetworkName } from './state.ts'

export const DEFAULT_ELECTRUM_PORT = 50001

export type Endpoint = { host: string; port: number }

export type Config = {
  dataDir: string
  statePath: string
  seedPath: string
  /** Optional BIP39 passphrase, stored 0600 beside the phrase. */
  passphrasePath: string
  /** Soroban JSON-RPC endpoint, already normalised to a full URL. */
  sorobanUrl: string
  electrumHost: string
  electrumPort: number
  /** Local HTTP port the storefront listens on; Tor maps the onion to it. */
  httpPort: number
  torSocks: SocksProxy
  /** Set when the operator has accepted exposing the watch list. See below. */
  allowRemoteIndexerOnMainnet: boolean
}

function env(name: string): string | undefined {
  const v = process.env[name]
  return v && v.length > 0 ? v : undefined
}

export function isOnion(host: string): boolean {
  return host.toLowerCase().endsWith('.onion')
}

/**
 * Loopback, link-local, or RFC1918 — i.e. the operator's own machine or their
 * own network, which is where a self-hosted Dojo lives (dojonet is 172.29.x).
 */
export function isLocalHost(host: string): boolean {
  const h = host.toLowerCase()
  if (h === 'localhost' || h === '::1' || h.startsWith('127.')) return true
  if (h.startsWith('10.') || h.startsWith('192.168.') || h.startsWith('169.254.')) return true
  const m = h.match(/^172\.(\d+)\./)
  return m !== null && Number(m[1]) >= 16 && Number(m[1]) <= 31
}

/**
 * Parse an indexer endpoint as Dojo Bay prints it — `tcp://host:port` — and
 * also accept `host:port` or a bare host, defaulting to the Electrum port.
 */
export function parseElectrumEndpoint(value: string, defaultPort = DEFAULT_ELECTRUM_PORT): Endpoint {
  let rest = value.trim()
  if (rest.length === 0) throw new Error('empty indexer endpoint')
  rest = rest.replace(/^tcp:\/\//i, '').replace(/\/+$/, '')

  const idx = rest.lastIndexOf(':')
  if (idx > 0) {
    const port = Number(rest.slice(idx + 1))
    const host = rest.slice(0, idx)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`invalid indexer port in "${value}"`)
    }
    if (host.length === 0) throw new Error(`invalid indexer host in "${value}"`)
    return { host, port }
  }
  return { host: rest, port: defaultPort }
}

/**
 * Normalise a Soroban address to a full RPC URL. Dojo Bay lists the onion bare,
 * with no scheme or port; its hidden service is virtual port 80 and the RPC
 * path is /rpc, so fill both in rather than making the operator work it out.
 */
export function normaliseSorobanUrl(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length === 0) throw new Error('empty soroban endpoint')
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`
  const url = new URL(withScheme)
  if (url.pathname === '/' || url.pathname === '') url.pathname = '/rpc'
  return url.toString()
}

/**
 * Can the hardened service actually execute this Node?
 *
 * The unit sets ProtectHome=yes, which makes /home, /root and /run/user
 * invisible to it, so a Node installed by nvm or into ~/.local yields an
 * ExecStart that could never run — failing at start with an unhelpful error.
 * install.sh deliberately resolves the invoking user's Node before escalating,
 * which is exactly the case that breaks, so this has to be checked explicitly.
 */
export function nodeIsReachableByService(execPath: string): boolean {
  return !/^\/(home|root|run\/user)(\/|$)/.test(execPath)
}

/** The proxy needed to reach `host`, or undefined when it is directly routable. */
export function proxyFor(host: string, config: Config): SocksProxy | undefined {
  return isOnion(host) ? config.torSocks : undefined
}

/**
 * Refuse to run mainnet against an indexer the operator does not control.
 *
 * Every address the bot watches is queried against the indexer, so whoever
 * answers learns the merchant's entire counterparty graph — precisely the
 * linkage this project exists to keep unwritten, and worse than the
 * notification transaction it removes. Harmless on testnet, where there are no
 * real counterparties, so the rule applies only to mainnet.
 */
export function assertIndexerAllowed(
  network: NetworkName,
  host: string,
  allowed: boolean,
): void {
  if (network !== 'mainnet' || isLocalHost(host) || allowed) return
  throw new Error(
    `refusing to run mainnet against the indexer at ${host}, which you do not control.\n` +
      `Every address this bot watches would be queried there, so its operator would learn\n` +
      `your entire customer list — the exact linkage skipping the notification transaction\n` +
      `is meant to avoid. Use your own Dojo for mainnet, or, if you genuinely accept that\n` +
      `exposure, set PAYNYM_BOT_ALLOW_REMOTE_INDEXER=yes.`,
  )
}

export function loadConfig(overrides: { dataDir?: string } = {}): Config {
  const dataDir = overrides.dataDir ?? env('PAYNYM_BOT_DATA') ?? join(homedir(), '.paynym-bot')
  const electrum = parseElectrumEndpoint(
    env('PAYNYM_BOT_ELECTRUM') ??
      `${env('PAYNYM_BOT_ELECTRUM_HOST') ?? '127.0.0.1'}:${env('PAYNYM_BOT_ELECTRUM_PORT') ?? DEFAULT_ELECTRUM_PORT}`,
  )
  return {
    dataDir,
    statePath: join(dataDir, 'state.json'),
    seedPath: join(dataDir, 'seed'),
    passphrasePath: join(dataDir, 'passphrase'),
    sorobanUrl: normaliseSorobanUrl(env('PAYNYM_BOT_SOROBAN') ?? 'http://127.0.0.1:4242/rpc'),
    electrumHost: electrum.host,
    electrumPort: electrum.port,
    httpPort: Number(env('PAYNYM_BOT_HTTP_PORT') ?? 8462),
    torSocks: {
      host: env('PAYNYM_BOT_TOR_SOCKS_HOST') ?? DEFAULT_TOR_SOCKS_HOST,
      port: Number(env('PAYNYM_BOT_TOR_SOCKS_PORT') ?? DEFAULT_TOR_SOCKS_PORT),
    },
    allowRemoteIndexerOnMainnet: (env('PAYNYM_BOT_ALLOW_REMOTE_INDEXER') ?? '').toLowerCase() === 'yes',
  }
}
