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
import { SorobanRPC, fetchTransport } from './soroban.ts'

const exec = promisify(execFile)

export const DOJO_NETWORK = 'dojonet'
export const FULCRUM_PORT = 50001
export const SOROBAN_PORT = 4242

export type Candidate = { host: string; port: number; why: string }
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
    const client = new ElectrumClient({ ...candidate, timeoutMs: 4_000 })
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
  return `http://${candidate.host}:${candidate.port}/rpc`
}

/**
 * Confirm Soroban with a read-only directory.List on a name nothing uses. A
 * live node answers with an entry list; anything else is not Soroban.
 */
export async function probeSoroban(candidates: Candidate[]): Promise<Discovery> {
  const attempts: Attempt[] = []
  for (const candidate of candidates) {
    try {
      const rpc = new SorobanRPC(fetchTransport(sorobanUrlFor(candidate), 4_000))
      await rpc.list('paynym-bot.probe')
      attempts.push({ candidate })
      return { found: candidate, attempts }
    } catch (err) {
      attempts.push({ candidate, error: (err as Error).message })
    }
  }
  return { found: null, attempts }
}

/** What to tell an operator when nothing answered. */
export function remedyFor(service: 'indexer' | 'soroban'): string {
  const name = service === 'indexer' ? 'Fulcrum' : 'Soroban'
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
