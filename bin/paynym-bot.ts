#!/usr/bin/env -S node --experimental-strip-types --no-warnings
// paynym-bot CLI.
//
//   paynym-bot init [--network mainnet|testnet] [--label <name>] [--data <dir>] [--force]
//                   [--mnemonic "<words>"] [--passphrase <p>]
//   paynym-bot status [--data <dir>]
//   paynym-bot serve [--data <dir>]          storefront only
//   paynym-bot start [--data <dir>]          storefront + listen + scan
//   paynym-bot doctor                        find the Dojo services, or say why not
//
// init is the guided setup: it asks which network to run on, generates the
// seed, and writes the state file. That network choice is permanent — see the
// note in src/state.ts.

import { parseArgs } from 'node:util'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { createInterface } from 'node:readline/promises'
import { PaynymIdentity } from '../src/identity.ts'
import { Registrar, Registry } from '../src/register.ts'
import { watchWindow } from '../src/watcher.ts'
import { SorobanRPC } from '../src/soroban.ts'
import { ElectrumClient, electrumUsedChecker } from '../src/electrum.ts'
import { Daemon } from '../src/daemon.ts'
import {
  FULCRUM_PORT,
  SOROBAN_PORT,
  candidatesFor,
  explicitCandidate,
  probeElectrum,
  probeSoroban,
  remedyFor,
  sorobanUrlFor,
} from '../src/discover.ts'
import {
  isValidMnemonic,
  newMnemonic,
  normaliseMnemonic,
  readSeedFile,
  seedFromMnemonic,
  writeMnemonicFile,
} from '../src/seed.ts'
import { assertIndexerAllowed, isOnion, loadConfig, proxyFor } from '../src/config.ts'
import { createStorefront } from '../src/server.ts'
import {
  assertNetworkMatches,
  isNetworkName,
  loadState,
  networkFor,
  newState,
  saveState,
} from '../src/state.ts'
import type { NetworkName } from '../src/state.ts'

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    network: { type: 'string' },
    data: { type: 'string' },
    label: { type: 'string' },
    mnemonic: { type: 'string' },
    passphrase: { type: 'string' },
    force: { type: 'boolean', default: false },
  },
})

const command = positionals[0]
const config = loadConfig({ dataDir: values.data })

function die(message: string): never {
  console.error(`error: ${message}`)
  process.exit(1)
}

/**
 * The network flag, refusing anything unrecognised. Silently ignoring a typo
 * would skip assertNetworkMatches entirely — the opposite of what someone
 * passing --network is asking for.
 */
function requestedNetwork(): NetworkName | undefined {
  if (values.network === undefined) return undefined
  if (!isNetworkName(values.network)) {
    die(`--network must be "mainnet" or "testnet", got "${values.network}"`)
  }
  return values.network
}

/** Ask which network to run on. Only reached when --network was not given. */
async function promptNetwork(): Promise<NetworkName> {
  if (!process.stdin.isTTY) {
    die('no --network given and stdin is not a terminal; pass --network mainnet|testnet')
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    console.log('\nWhich network should this receiver run on?')
    console.log('  1) testnet  — recommended first; rehearse the whole flow with no real money')
    console.log('  2) mainnet  — real funds\n')
    console.log('This choice is permanent. It fixes the BIP47 derivation path and therefore')
    console.log('the PayNym itself, so it cannot be changed later without becoming a')
    console.log('different receiver and orphaning every customer already registered.\n')
    for (;;) {
      const answer = (await rl.question('network [1=testnet, 2=mainnet]: ')).trim().toLowerCase()
      if (answer === '1' || answer === 'testnet') return 'testnet'
      if (answer === '2' || answer === 'mainnet') return 'mainnet'
      console.log('please answer 1 or 2 (or "testnet" / "mainnet")')
    }
  } finally {
    rl.close()
  }
}

function loadSeed(path: string): Uint8Array {
  // The installer stores a passphrase beside the phrase at 0600 rather than in
  // the unit file, which is world-readable by default.
  const stored = existsSync(config.passphrasePath)
    ? readFileSync(config.passphrasePath, 'utf8').trim()
    : ''
  try {
    return readSeedFile(path, values.passphrase ?? stored).seed
  } catch (err) {
    return die((err as Error).message)
  }
}

/** Ask for an existing mnemonic, re-prompting until the checksum validates. */
async function promptMnemonic(): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    console.log('\nPaste your BIP39 mnemonic (12 or 24 words).')
    for (;;) {
      const answer = await rl.question('mnemonic: ')
      if (isValidMnemonic(answer)) return normaliseMnemonic(answer)
      console.log('  that is not a valid mnemonic — the checksum does not match.')
      console.log('  check for a mistyped or out-of-order word, then try again.')
    }
  } finally {
    rl.close()
  }
}

/** Show a freshly generated mnemonic once, and make the operator acknowledge it. */
async function presentMnemonic(mnemonic: string): Promise<void> {
  const words = mnemonic.split(' ')
  console.log('\n  Wallet recovery phrase — written down now, or not at all:\n')
  for (let i = 0; i < words.length; i += 4) {
    const row = words
      .slice(i, i + 4)
      .map((w, j) => `${String(i + j + 1).padStart(2)}. ${w.padEnd(10)}`)
      .join('')
    console.log(`    ${row}`)
  }
  console.log('\n  This is shown once and never again.')
  console.log('  It is NOT a complete backup on its own: a BIP47 receive address depends')
  console.log('  on both parties\' payment codes, so without state.json money already')
  console.log('  received cannot be found. Back up the phrase AND the state file.\n')

  if (!process.stdin.isTTY) return
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    while ((await rl.question('type "written" once you have recorded it: ')).trim().toLowerCase() !== 'written') {
      console.log('  please type: written')
    }
  } finally {
    rl.close()
  }
}

async function init(): Promise<void> {
  if (values.network !== undefined && !isNetworkName(values.network)) {
    die(`--network must be "mainnet" or "testnet", got "${values.network}"`)
  }
  if (existsSync(config.statePath) && !values.force) {
    die(
      `state already exists at ${config.statePath}. Refusing to overwrite it — it holds the ` +
        `customer payment codes needed to find money already received. Use --data <dir> for a ` +
        `separate deployment, or --force only if you are certain.`,
    )
  }

  const network = isNetworkName(values.network) ? values.network : await promptNetwork()

  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 })

  // Either import an existing wallet or mint a new one. Imported first: an
  // operator bringing a PayNym they already own must not have one invented for
  // them, and a mnemonic passed on the command line is an unambiguous request.
  let mnemonic: string
  let generated = false
  if (values.mnemonic !== undefined) {
    if (!isValidMnemonic(values.mnemonic)) {
      die('--mnemonic is not a valid BIP39 phrase: the checksum does not match')
    }
    mnemonic = normaliseMnemonic(values.mnemonic)
  } else if (process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    let importing: boolean
    try {
      const answer = (await rl.question('\nimport an existing wallet? [y/N]: ')).trim().toLowerCase()
      importing = answer === 'y' || answer === 'yes'
    } finally {
      rl.close()
    }
    mnemonic = importing ? await promptMnemonic() : newMnemonic()
    generated = !importing
  } else {
    mnemonic = newMnemonic()
    generated = true
  }

  const passphrase = values.passphrase ?? ''
  // Derived before anything is written, so an unusable phrase fails here rather
  // than leaving a half-initialised data directory behind.
  const seed = seedFromMnemonic(mnemonic, passphrase)

  if (generated) await presentMnemonic(mnemonic)

  // The wallet is persisted before the state file, so state can never refer to
  // a seed that was not written.
  writeMnemonicFile(config.seedPath, mnemonic)
  saveState(config.statePath, newState(network, Date.now(), values.label))

  const identity = PaynymIdentity.fromSeed(seed, networkFor(network))

  console.log(`\n  network:        ${network}`)
  console.log(`\n  PayNym (pay me here):\n\n    ${identity.paymentCode()}\n`)
  console.log(`  notification address: ${identity.notificationAddress()}`)
  console.log(`  (shown for reference — customers of this bot never pay it)\n`)
  console.log(`  wallet: ${config.seedPath}   (12-word BIP39 phrase)`)
  console.log(`  state:  ${config.statePath}\n`)
  console.log('  Back up BOTH. The recovery phrase alone is not enough: BIP47 receive')
  console.log('  keys depend on the customer payment codes held in the state file, so')
  console.log('  without it, money already received cannot be found.\n')
  if (passphrase.length > 0) {
    console.log('  A BIP39 passphrase is in use. On an always-online box it adds no')
    console.log('  security, since it must be supplied to the running service — it exists')
    console.log('  so an imported wallet derives the same PayNym as in your wallet app.')
    console.log('  You must pass --passphrase on every command, or the PayNym differs.\n')
  }
}

function status(): void {
  const state = loadState(config.statePath)
  const wanted = requestedNetwork()
  if (wanted !== undefined) assertNetworkMatches(state, wanted)

  const identity = PaynymIdentity.fromSeed(
    loadSeed(config.seedPath),
    networkFor(state.network),
  )
  const registry = Registry.fromJSON(state.senders)
  const window = watchWindow(identity, registry)

  console.log(`\n  network:            ${state.network}`)
  console.log(`  PayNym:             ${identity.paymentCode()}`)
  console.log(`  published as:       ${config.onion ?? state.onion ?? '(unset — scan-to-pay disabled)'}`)
  console.log(`  registered senders: ${state.senders.length}`)
  console.log(`  addresses watched:  ${window.length}`)
  if (window.length > 0) {
    console.log('\n  next receive addresses:')
    for (const w of window.slice(0, 5)) {
      console.log(`    [${w.index}] ${w.address}`)
    }
  }
  console.log('')
}

/**
 * Say plainly whether scan-to-pay is on. The auth47 flow binds every proof to
 * the host the storefront is published as, and refuses to serve without one —
 * so an operator who sees the page work but the QR missing needs to be told
 * why, and told the one thing that fixes it.
 */
function announceOnion(onion: string | undefined, httpPort: number): void {
  if (onion) {
    console.log(`  published as:  ${onion}  (scan-to-pay enabled)\n`)
    return
  }
  console.log('  scan-to-pay (auth47) is DISABLED: no published host is configured.')
  console.log('  An auth47 proof is bound to the host it was signed for, and that host')
  console.log('  must come from you, not from the request — otherwise a proof minted for')
  console.log('  another site authenticates here. Set it once and it stays set:')
  console.log('    PAYNYM_BOT_ONION=yourshop.onion   (or the "onion" field in state.json)')
  console.log(`  For local development, use the host you browse to: 127.0.0.1:${httpPort}\n`)
}

function serve(): void {
  const state = loadState(config.statePath)
  const wanted = requestedNetwork()
  if (wanted !== undefined) assertNetworkMatches(state, wanted)

  const identity = PaynymIdentity.fromSeed(
    loadSeed(config.seedPath),
    networkFor(state.network),
  )
  const registry = Registry.fromJSON(state.senders)
  const server = createStorefront({
    identity,
    network: state.network,
    label: values.label ?? state.label,
    // Address sessions need the registry; serve is storefront-only, so the
    // persistence callback writes the state file only when a customer
    // authenticates — cheap, and correct across restarts.
    registry,
    persist: async () => {
      saveState(config.statePath, { ...state, senders: registry.toJSON() })
    },
    // Auth47 is bound to this host and is not served without it. See
    // StorefrontOptions.onionHost.
    onionHost: config.onion ?? state.onion,
  })

  // Loopback only. Tor terminates the onion and forwards here; binding any
  // wider would expose the storefront on the clearnet interface too.
  server.listen(config.httpPort, '127.0.0.1', () => {
    console.log(`\n  storefront:  http://127.0.0.1:${config.httpPort}`)
    console.log(`  network:     ${state.network}`)
    console.log(`  PayNym:      ${identity.paymentCode().slice(0, 24)}...\n`)
    console.log('  Publish it by pointing a Tor hidden service at that port, e.g. in torrc:')
    console.log('    HiddenServiceDir /var/lib/tor/paynym-bot/')
    console.log(`    HiddenServicePort 80 127.0.0.1:${config.httpPort}\n`)
    announceOnion(config.onion ?? state.onion, config.httpPort)
    console.log('  Ctrl-C to stop.')
  })

  const shutdown = () => {
    server.close(() => process.exit(0))
    // Do not hang forever on a client holding the socket open.
    setTimeout(() => process.exit(0), 3000).unref()
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

function start(): void {
  const state = loadState(config.statePath)
  const wanted = requestedNetwork()
  if (wanted !== undefined) assertNetworkMatches(state, wanted)

  const network = networkFor(state.network)
  const identity = PaynymIdentity.fromSeed(loadSeed(config.seedPath), network)
  const registry = Registry.fromJSON(state.senders)
  const registrar = new Registrar(identity, registry)

  // Refuse before anything starts: on mainnet, an indexer the operator does not
  // control would learn the whole customer list.
  try {
    assertIndexerAllowed(state.network, config.electrumHost, config.allowRemoteIndexerOnMainnet)
  } catch (err) {
    die((err as Error).message)
  }

  const sorobanHost = new URL(config.sorobanUrl).hostname
  const rpc = SorobanRPC.forUrl(config.sorobanUrl, proxyFor(sorobanHost, config))
  const electrum = new ElectrumClient({
    host: config.electrumHost,
    port: config.electrumPort,
    proxy: proxyFor(config.electrumHost, config),
    // A Tor circuit takes seconds to build, where loopback takes none.
    timeoutMs: isOnion(config.electrumHost) ? 30_000 : 10_000,
  })

  const daemon = new Daemon({
    identity,
    registrar,
    rpc,
    isUsed: electrumUsedChecker(electrum, network),
    // Rewrite the whole record set: it is small, and an atomic replace cannot
    // leave a half-updated registry behind.
    persist: async () => {
      saveState(config.statePath, { ...state, senders: registry.toJSON() })
    },
    log: (line) => console.log(`[${new Date().toISOString()}] ${line}`),
  })

  const server = createStorefront({
    identity,
    network: state.network,
    label: values.label ?? state.label,
    // The daemon and the storefront share one registry instance: a customer
    // authenticated via auth47 becomes a watched sender immediately, and a
    // payment credited by the scan loop advances the index the storefront
    // hands out next.
    registry,
    persist: async () => {
      saveState(config.statePath, { ...state, senders: registry.toJSON() })
    },
    onionHost: config.onion ?? state.onion,
  })

  server.listen(config.httpPort, '127.0.0.1', () => {
    console.log(`\n  network:     ${state.network}`)
    console.log(`  PayNym:      ${identity.paymentCode()}`)
    console.log(`  storefront:  http://127.0.0.1:${config.httpPort}`)
    console.log(`  soroban:     ${config.sorobanUrl}${isOnion(sorobanHost) ? '  (via Tor)' : ''}`)
    console.log(
      `  indexer:     ${config.electrumHost}:${config.electrumPort}` +
        `${isOnion(config.electrumHost) ? '  (via Tor)' : ''}`,
    )
    console.log(`  customers:   ${state.senders.length}\n`)
    announceOnion(config.onion ?? state.onion, config.httpPort)
    daemon.start()
  })

  const shutdown = () => {
    daemon.stop()
    electrum.close()
    server.close(() => process.exit(0))
    setTimeout(() => process.exit(0), 3000).unref()
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

/**
 * Diagnose the connection to the local Dojo. The installer runs the same probes;
 * having it as a command means an operator can re-run the diagnosis later
 * without reinstalling, which is when they will actually need it.
 */
async function doctor(): Promise<void> {
  let ok = true

  for (const [label, container, port] of [
    ['indexer (Fulcrum)', 'fulcrum', FULCRUM_PORT],
    ['soroban', 'soroban', SOROBAN_PORT],
  ] as const) {
    // An explicitly configured onion is checked as given; only an unconfigured
    // endpoint gets the local discovery sweep.
    const configuredHost =
      container === 'fulcrum' ? config.electrumHost : new URL(config.sorobanUrl).hostname
    const configuredPort =
      container === 'fulcrum' ? config.electrumPort : Number(new URL(config.sorobanUrl).port || 80)
    // Probe what will actually run. Falling back to local discovery whenever the
    // endpoint is not an onion would diagnose a different deployment than the
    // one that starts — and doctor is the first thing an operator runs.
    const configured =
      container === 'fulcrum'
        ? process.env.PAYNYM_BOT_ELECTRUM !== undefined ||
          process.env.PAYNYM_BOT_ELECTRUM_HOST !== undefined ||
          isOnion(configuredHost)
        : process.env.PAYNYM_BOT_SOROBAN !== undefined || isOnion(configuredHost)
    const candidates = configured
      ? explicitCandidate(configuredHost, configuredPort, config.torSocks)
      : await candidatesFor(container, port)
    const result =
      container === 'fulcrum' ? await probeElectrum(candidates) : await probeSoroban(candidates)

    console.log(`\n  ${label}`)
    for (const attempt of result.attempts) {
      const { host, port: p, why } = attempt.candidate
      const mark = attempt.error ? '·' : '✓'
      const detail = attempt.error ? `  (${attempt.error})` : ''
      console.log(`    ${mark} ${host}:${p}  ${why}${detail}`)
    }
    if (result.found) {
      const { host, port: p } = result.found
      console.log(`    -> using ${container === 'soroban' ? sorobanUrlFor(result.found) : `${host}:${p}`}`)
    } else {
      ok = false
      console.log('')
      const viaTor = isOnion(configuredHost)
      for (const line of remedyFor(container === 'fulcrum' ? 'indexer' : 'soroban', viaTor).split('\n')) {
        console.log(`    ${line}`)
      }
    }
  }

  console.log('')
  if (!ok) process.exit(1)
}

try {
  if (command === 'init') await init()
  else if (command === 'status') status()
  else if (command === 'serve') serve()
  else if (command === 'start') start()
  else if (command === 'doctor') await doctor()
  else {
    console.error(
      'usage: paynym-bot <init|status|serve|start|doctor> ' +
        '[--network mainnet|testnet] [--label <name>] [--data <dir>]',
    )
    process.exit(1)
  }
} catch (err) {
  die((err as Error).message)
}
