// Finding the Dojo services this bot depends on.
//
// Dojo runs its services in Docker on a private `dojonet` bridge, and its own
// documentation warns against publishing those ports to the host. So the
// endpoints a process outside Docker should use are NOT knowable in advance —
// depending on how the operator set things up, the indexer may be on loopback,
// reachable via the bridge gateway, or only at the container's own address.
//
// So probe rather than assume, and prove reachability with a real protocol
// exchange rather than an open port: a listening socket that is not Fulcrum is
// worse than nothing, because it fails later and less legibly.

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { ElectrumClient } from './electrum.ts'
import { SorobanRPC, fetchTransport, socksTransport } from './soroban.ts'
import { isOnion } from './config.ts'
import type { SocksProxy } from './socks.ts'

const exec = promisify(execFile)

export const DOJO_NETWORK = 'dojonet'
export const FULCRUM_PORT = 50001
export const SOROBAN_PORT = 4242

export type Candidate = {
  host: string
  port: number
  why: string
  /** Set when this candidate is an onion and must be reached through Tor. */
  proxy?: SocksProxy
}

/**
 * A single explicitly configured endpoint, still probed rather than trusted.
 * Used when the operator names a remote Dojo instead of relying on discovery.
 */
export function explicitCandidate(
  host: string,
  port: number,
  torSocks: SocksProxy,
): Candidate[] {
  return [
    {
      host,
      port,
      why: isOnion(host) ? 'configured onion' : 'configured endpoint',
      proxy: isOnion(host) ? torSocks : undefined,
    },
  ]
}
export type Attempt = { candidate: Candidate; error?: string }
export type Discovery = { found: Candidate | null; attempts: Attempt[] }

/** Run a command, returning stdout or null if it is unavailable or fails. */
async function tryCommand(cmd: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await exec(cmd, args, { timeout: 5_000 })
    const out = stdout.trim()
    return out.length > 0 ? out : null
  } catch {
    return null // docker absent, daemon down, or no such network — all fine
  }
}

/** Gateway address of the Dojo bridge network, if the host can see it. */
export async function dockerGateway(network = DOJO_NETWORK): Promise<string | null> {
  const out = await tryCommand('docker', [
    'network',
    'inspect',
    network,
    '--format',
    '{{range .IPAM.Config}}{{.Gateway}} {{end}}',
  ])
  return out?.split(/\s+/).find((v) => /^\d+\.\d+\.\d+\.\d+$/.test(v)) ?? null
}

/** Address of the first running container whose name matches `pattern`. */
export async function dockerContainerIp(
  pattern: string,
  network = DOJO_NETWORK,
): Promise<string | null> {
  const names = await tryCommand('docker', [
    'ps',
    '--filter',
    `name=${pattern}`,
    '--format',
    '{{.Names}}',
  ])
  const name = names?.split('\n')[0]?.trim()
  if (!name) return null

  const ip = await tryCommand('docker', [
    'inspect',
    name,
    '--format',
    `{{with index .NetworkSettings.Networks "${network}"}}{{.IPAddress}}{{end}}`,
  ])
  return ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip : null
}

/**
 * Where a service might be, most conventional first: published to the host,
 * then via the bridge gateway, then the container's own address.
 */
export async function candidatesFor(
  containerPattern: string,
  port: number,
): Promise<Candidate[]> {
  const out: Candidate[] = [
    { host: '127.0.0.1', port, why: 'published to the host' },
  ]
  const gateway = await dockerGateway()
  if (gateway) out.push({ host: gateway, port, why: `${DOJO_NETWORK} bridge gateway` })
  const container = await dockerContainerIp(containerPattern)
  if (container) out.push({ host: container, port, why: `${containerPattern} container` })
  return out
}

/** Confirm Fulcrum by asking it for its version, not by opening a socket. */
export async function probeElectrum(candidates: Candidate[]): Promise<Discovery> {
  const attempts: Attempt[] = []
  for (const candidate of candidates) {
    // Onions are slow enough that a local-probe timeout would fail them
    // spuriously; a Tor circuit routinely takes several seconds to build.
    const client = new ElectrumClient({
      ...candidate,
      timeoutMs: candidate.proxy ? 30_000 : 4_000,
    })
    try {
      await client.serverVersion()
      attempts.push({ candidate })
      return { found: candidate, attempts }
    } catch (err) {
      attempts.push({ candidate, error: (err as Error).message })
    } finally {
      client.close()
    }
  }
  return { found: null, attempts }
}

export function sorobanUrlFor(candidate: Candidate): string {
  // An onion's hidden service is virtual port 80, which is the default, so
  // leave it off and keep the URL in the form Dojo Bay prints.
  const authority = candidate.port === 80 ? candidate.host : `${candidate.host}:${candidate.port}`
  return `http://${authority}/rpc`
}

/**
 * Confirm Soroban with a read-only directory.List on a name nothing uses. A
 * live node answers with an entry list; anything else is not Soroban.
 */
export async function probeSoroban(candidates: Candidate[]): Promise<Discovery> {
  const attempts: Attempt[] = []
  for (const candidate of candidates) {
    try {
      const url = sorobanUrlFor(candidate)
      const rpc = new SorobanRPC(
        candidate.proxy ? socksTransport(url, candidate.proxy, 30_000) : fetchTransport(url, 4_000),
      )
      await rpc.list('paynym-bot.probe')
      attempts.push({ candidate })
      return { found: candidate, attempts }
    } catch (err) {
      attempts.push({ candidate, error: (err as Error).message })
    }
  }
  return { found: null, attempts }
}

/**
 * What to tell an operator when nothing answered. A configured onion that fails
 * is almost always Tor, not the Dojo, so do not send them off to reconfigure a
 * machine that is fine.
 */
export function remedyFor(service: 'indexer' | 'soroban', viaTor = false): string {
  const name = service === 'indexer' ? 'Fulcrum' : 'Soroban'
  if (viaTor) {
    return [
      `Could not reach ${name} over Tor.`,
      '',
      'The address is an onion service, so this is usually the local Tor daemon',
      'rather than the remote Dojo:',
      '  * is tor running?   systemctl status tor',
      '  * is its SOCKS port reachable?   default 127.0.0.1:9050',
      '  * override it with PAYNYM_BOT_TOR_SOCKS_HOST / _PORT',
      '',
      'If Tor is fine, the remote operator may not publish this service — it is',
      `optional in a Dojo (INDEXER_INSTALL / SOROBAN_INSTALL). Try another node.`,
    ].join('\n')
  }
  return [
    `Could not reach ${name} on any candidate address.`,
    '',
    `Dojo keeps its services on the private "${DOJO_NETWORK}" Docker network, so a`,
    'process on the host cannot always reach them. Any one of these fixes it:',
    service === 'indexer'
      ? `  * enable the indexer in your Dojo configuration (it is optional in some setups)`
      : `  * enable Soroban in your Dojo configuration`,
    `  * publish the port to 127.0.0.1 in your Dojo docker-compose override`,
    `  * run paynym-bot as a container attached to ${DOJO_NETWORK}`,
    '',
    'Set the address explicitly if you know it: PAYNYM_BOT_' +
      (service === 'indexer' ? 'ELECTRUM_HOST / _PORT' : 'SOROBAN'),
  ].join('\n')
}
