#!/usr/bin/env -S node --experimental-strip-types --no-warnings
// paynym-bot CLI.
//
//   paynym-bot init [--network mainnet|testnet] [--data <dir>] [--force]
//   paynym-bot status [--data <dir>]
//
// init is the guided setup: it asks which network to run on, generates the
// seed, and writes the state file. That network choice is permanent — see the
// note in src/state.ts.

import { parseArgs } from 'node:util'
import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline/promises'
import { PaynymIdentity } from '../src/identity.ts'
import { Registry } from '../src/register.ts'
import { watchWindow } from '../src/watcher.ts'
import { loadConfig } from '../src/config.ts'
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
    force: { type: 'boolean', default: false },
  },
})

const command = positionals[0]
const config = loadConfig({ dataDir: values.data })

function die(message: string): never {
  console.error(`error: ${message}`)
  process.exit(1)
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
  if (!existsSync(path)) die(`no seed at ${path} — run "paynym-bot init" first`)
  const hex = readFileSync(path, 'utf8').trim()
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) die(`seed at ${path} is not hex`)
  return Uint8Array.from(Buffer.from(hex, 'hex'))
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

  // A fresh 64-byte BIP32 master seed. Written before the state file so we can
  // never end up with state referring to a seed that was not persisted.
  const seed = randomBytes(64)
  writeFileSync(config.seedPath, `${seed.toString('hex')}\n`, { mode: 0o600 })
  chmodSync(config.seedPath, 0o600)

  saveState(config.statePath, newState(network))

  const identity = PaynymIdentity.fromSeed(
    Uint8Array.from(seed),
    networkFor(network),
  )

  console.log(`\n  network:        ${network}`)
  console.log(`\n  PayNym (pay me here):\n\n    ${identity.paymentCode()}\n`)
  console.log(`  notification address: ${identity.notificationAddress()}`)
  console.log(`  (shown for reference — customers of this bot never pay it)\n`)
  console.log(`  seed:  ${config.seedPath}`)
  console.log(`  state: ${config.statePath}\n`)
  console.log('  Back up BOTH files. The seed alone is not enough: BIP47 receive keys')
  console.log('  depend on the customer payment codes held in the state file, so without')
  console.log('  it, money already received cannot be found.\n')
}

function status(): void {
  const state = loadState(config.statePath)
  if (isNetworkName(values.network)) assertNetworkMatches(state, values.network)

  const identity = PaynymIdentity.fromSeed(
    loadSeed(config.seedPath),
    networkFor(state.network),
  )
  const registry = Registry.fromJSON(state.senders)
  const window = watchWindow(identity, registry)

  console.log(`\n  network:            ${state.network}`)
  console.log(`  PayNym:             ${identity.paymentCode()}`)
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

try {
  if (command === 'init') await init()
  else if (command === 'status') status()
  else {
    console.error('usage: paynym-bot <init|status> [--network mainnet|testnet] [--data <dir>]')
    process.exit(1)
  }
} catch (err) {
  die((err as Error).message)
}
