// Runtime configuration: where state lives and what local services to talk to.
//
// Everything the bot talks to is local to the deployment — Soroban and the
// indexer both sit beside it on the Dojo host — so the bot never opens an
// outbound Tor connection and needs no SOCKS client. Tor is torrc
// configuration for the hidden service the bot EXPOSES, not something this
// code speaks.

import { homedir } from 'node:os'
import { join } from 'node:path'

export type Config = {
  dataDir: string
  statePath: string
  seedPath: string
  /** Soroban JSON-RPC endpoint. Confirm the port against your deployment. */
  sorobanUrl: string
  /** Fulcrum / electrs, Electrum protocol over TCP. Dojo exposes 50001. */
  electrumHost: string
  electrumPort: number
  /** Local HTTP port the storefront listens on; Tor maps the onion to it. */
  httpPort: number
}

function env(name: string): string | undefined {
  const v = process.env[name]
  return v && v.length > 0 ? v : undefined
}

export function loadConfig(overrides: { dataDir?: string } = {}): Config {
  const dataDir =
    overrides.dataDir ?? env('PAYNYM_BOT_DATA') ?? join(homedir(), '.paynym-bot')
  return {
    dataDir,
    statePath: join(dataDir, 'state.json'),
    seedPath: join(dataDir, 'seed'),
    sorobanUrl: env('PAYNYM_BOT_SOROBAN') ?? 'http://127.0.0.1:4242/rpc',
    electrumHost: env('PAYNYM_BOT_ELECTRUM_HOST') ?? '127.0.0.1',
    electrumPort: Number(env('PAYNYM_BOT_ELECTRUM_PORT') ?? 50001),
    httpPort: Number(env('PAYNYM_BOT_HTTP_PORT') ?? 8462),
  }
}
