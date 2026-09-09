// paynym-bot installer.
//
// Run via ../install.sh, which resolves Node and escalates. Everything that
// touches the system goes through `act`, so --dry-run can print an exact
// account of what a real run would do without doing any of it.

import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline/promises'
import { join } from 'node:path'
import { PaynymIdentity } from '../src/identity.ts'
import { networkFor, newState, saveState } from '../src/state.ts'
import { isValidMnemonic, newMnemonic, normaliseMnemonic, seedFromMnemonic } from '../src/seed.ts'
import { mergeTorrc } from '../src/torrc.ts'
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
  DEFAULT_ELECTRUM_PORT,
  assertIndexerAllowed,
  isOnion,
  nodeIsReachableByService,
  normaliseSorobanUrl,
  parseElectrumEndpoint,
} from '../src/config.ts'
import { DEFAULT_TOR_SOCKS_HOST, DEFAULT_TOR_SOCKS_PORT } from '../src/socks.ts'
import type { NetworkName } from '../src/state.ts'

const TOR_SOCKS = { host: DEFAULT_TOR_SOCKS_HOST, port: DEFAULT_TOR_SOCKS_PORT }

/** Value of `--flag x`, or undefined. */
function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 ? process.argv[i + 1] : undefined
}


const DRY = process.argv.includes('--dry-run')

const SERVICE_USER = 'paynym-bot'
const DEFAULT_ROOT = '/opt/paynym-bot'
const DEFAULT_DATA = '/var/lib/paynym-bot'
const TOR_SERVICE_DIR = '/var/lib/tor/paynym-bot'
const TORRC = '/etc/tor/torrc'
const UNIT = '/etc/systemd/system/paynym-bot.service'
const DEFAULT_HTTP_PORT = 8462

const REPO = join(import.meta.dirname, '..')

let step = 0
const heading = (t: string) => console.log(`\n\x1b[1m${++step}. ${t}\x1b[0m`)
const info = (t: string) => console.log(`   ${t}`)
const warn = (t: string) => console.log(`   \x1b[33m! ${t}\x1b[0m`)
const die = (t: string): never => {
  console.error(`\n\x1b[31merror:\x1b[0m ${t}\n`)
  process.exit(1)
}

/** Perform a mutation, or describe it under --dry-run. */
function act(description: string, fn: () => void): void {
  if (DRY) {
    console.log(`   \x1b[2mwould:\x1b[0m ${description}`)
    return
  }
  info(description)
  fn()
}

function sh(cmd: string, args: string[]): string {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
}

function has(cmd: string): boolean {
  try {
    sh('command', ['-v', cmd])
    return true
  } catch {
    try {
      sh('sh', ['-c', `command -v ${cmd}`])
      return true
    } catch {
      return false
    }
  }
}

const rl = createInterface({ input: process.stdin, output: process.stdout })
const ask = async (q: string, fallback = ''): Promise<string> => {
  if (DRY && !process.stdin.isTTY) return fallback
  const answer = (await rl.question(`   ${q}`)).trim()
  return answer.length > 0 ? answer : fallback
}
const confirm = async (q: string): Promise<boolean> =>
  ['y', 'yes'].includes((await ask(`${q} [y/N]: `)).toLowerCase())

try {
  console.log('\n\x1b[1mpaynym-bot installer\x1b[0m')
  if (DRY) console.log('\x1b[2m(dry run — nothing will be changed)\x1b[0m')

  // --- 1. Preflight ---------------------------------------------------------
  heading('Preflight')
  if (!DRY) {
    if (process.getuid?.() !== 0) {
      die('run as root: the installer writes torrc, a systemd unit and /opt. Use ./install.sh')
    }
    if (!process.stdin.isTTY) die('the installer is interactive; run it from a terminal')
  }
  const major = Number(process.versions.node.split('.')[0])
  if (major < 22) die(`Node 22+ required, found ${process.versions.node}`)

  const nodeBin = flag('node-bin') ?? process.execPath
  info(`node ${process.versions.node} at ${nodeBin}`)
  if (!nodeIsReachableByService(nodeBin)) {
    die(
      `${nodeBin} sits under a home directory, and the service runs with\n` +
        `   ProtectHome=yes, so it could never execute that path.\n\n` +
        `   Install a system-wide Node — the README has the NodeSource commands,\n` +
        `   which put it in /usr/bin — or point at one you already have:\n` +
        `     ./install.sh --node-bin /usr/bin/node\n\n` +
        `   Weakening the sandbox is not the answer: this process holds a hot key.`,
    )
  }

  if (!has('tor')) {
    warn('tor is not installed — the storefront cannot be published without it')
    if (DRY) {
      info('a real run would offer to apt-get install tor here')
    } else if (await confirm('install tor now?')) {
      act('apt-get install -y tor', () => {
        sh('apt-get', ['update'])
        sh('apt-get', ['install', '-y', 'tor'])
      })
    } else {
      die('tor is required')
    }
  } else {
    info('tor is present')
  }

  // --- 2. Where -------------------------------------------------------------
  heading('Locations')
  const root = await ask(`install root [${DEFAULT_ROOT}]: `, DEFAULT_ROOT)
  const dataDir = await ask(`data directory [${DEFAULT_DATA}]: `, DEFAULT_DATA)
  if (!root.startsWith('/') || !dataDir.startsWith('/')) die('paths must be absolute')
  const httpPort = Number(await ask(`local storefront port [${DEFAULT_HTTP_PORT}]: `, String(DEFAULT_HTTP_PORT)))
  if (!Number.isInteger(httpPort) || httpPort < 1 || httpPort > 65535) die('invalid port')

  if (existsSync(join(dataDir, 'state.json')) && !process.argv.includes('--force')) {
    die(
      `${join(dataDir, 'state.json')} already exists. It holds the customer payment ` +
        'codes needed to find money already received — refusing to overwrite. Choose ' +
        'another data directory, or pass --force if you are certain.',
    )
  }

  // --- 3. Network -----------------------------------------------------------
  heading('Network')
  info('This choice is permanent: it fixes the BIP47 derivation path and therefore')
  info('the PayNym itself, so it cannot be changed without becoming a different')
  info('receiver and orphaning every customer already registered.')
  let network: NetworkName | null = null
  while (network === null) {
    const answer = (await ask('network [1=testnet (recommended), 2=mainnet]: ', 'testnet')).toLowerCase()
    if (answer === '1' || answer === 'testnet') network = 'testnet'
    else if (answer === '2' || answer === 'mainnet') network = 'mainnet'
    else info('please answer 1 or 2')
  }
  info(`using ${network}`)
  const label = await ask('shop name shown on the page (optional): ')

  // --- 4. Wallet ------------------------------------------------------------
  heading('Wallet')
  let mnemonic: string
  let generated = false
  if (await confirm('import an existing recovery phrase?')) {
    for (;;) {
      const phrase = await ask('phrase: ')
      if (isValidMnemonic(phrase)) {
        mnemonic = normaliseMnemonic(phrase)
        break
      }
      warn('invalid: the BIP39 checksum does not match. Check for a mistyped word.')
    }
  } else {
    mnemonic = newMnemonic()
    generated = true
  }
  // A passphrase changes the wallet entirely. It adds no security here — it
  // must sit beside the phrase for the service to start — but an imported
  // wallet created with one derives a different PayNym without it, and the
  // operator would only discover that when payments never arrived.
  let passphrase = flag('passphrase') ?? ''
  if (!generated && passphrase.length === 0 && !DRY) {
    if (await confirm('does that phrase use a BIP39 passphrase?')) {
      passphrase = await ask('passphrase: ')
    }
  }
  const seed = seedFromMnemonic(mnemonic, passphrase)
  const identity = PaynymIdentity.fromSeed(seed, networkFor(network))

  if (!generated) {
    // The cheapest guard against silently installing the wrong wallet.
    info('')
    info(`This phrase derives: ${identity.paymentCode()}`)
    if (!DRY && !(await confirm('does that match the PayNym you expect?'))) {
      die('stopping: check the phrase, and the passphrase if the wallet uses one')
    }
  }

  if (generated) {
    const words = mnemonic.split(' ')
    console.log('\n   \x1b[1mRecovery phrase — written down now, or not at all:\x1b[0m\n')
    for (let i = 0; i < words.length; i += 4) {
      console.log(
        `     ${words.slice(i, i + 4).map((w, j) => `${String(i + j + 1).padStart(2)}. ${w.padEnd(10)}`).join('')}`,
      )
    }
    console.log('')
    warn('Shown once. It is NOT a complete backup on its own: a BIP47 receive address')
    warn('depends on both parties\' payment codes, so without state.json money already')
    warn('received cannot be found. Back up the phrase AND the data directory.')
    if (!DRY) {
      while ((await ask('\n   type "written" to continue: ')).toLowerCase() !== 'written') {
        info('please type: written')
      }
    }
  }

  // --- 5. Find the Dojo -----------------------------------------------------
  heading('Dojo services')

  // Two shapes, and they can be mixed. A remote testnet indexer with a local
  // Soroban is how an operator whose only Dojo is mainnet rehearses on testnet.
  const remote = await confirm('is your Dojo remote, published as onion services?')
  let electrumCandidates
  let sorobanCandidates
  let sorobanUrlOverride: string | undefined
  if (remote) {
    info('Dojo Bay lists these; paste them exactly as shown.')
    let parsed
    for (;;) {
      try {
        parsed = parseElectrumEndpoint(
          await ask(`indexer (tcp://…onion:${DEFAULT_ELECTRUM_PORT}): `),
          DEFAULT_ELECTRUM_PORT,
        )
        break
      } catch (err) {
        warn((err as Error).message)
      }
    }
    let sorobanUrlInput
    for (;;) {
      try {
        sorobanUrlInput = new URL(normaliseSorobanUrl(await ask('soroban rpc (…onion): ')))
        break
      } catch (err) {
        warn((err as Error).message)
      }
    }
    electrumCandidates = explicitCandidate(parsed.host, parsed.port, TOR_SOCKS)
    sorobanCandidates = explicitCandidate(
      sorobanUrlInput.hostname,
      Number(sorobanUrlInput.port || 80),
      TOR_SOCKS,
    )
    // Keep what the operator gave us: sorobanUrlFor rebuilds http://host/rpc,
    // which silently discards a non-root RPC path and fails the probe.
    sorobanUrlOverride = sorobanUrlInput.toString()
    info('reaching these over Tor; a circuit takes a few seconds to build.')
  } else {
    electrumCandidates = await candidatesFor('fulcrum', FULCRUM_PORT)
    sorobanCandidates = await candidatesFor('soroban', SOROBAN_PORT)
  }

  const electrum = await probeElectrum(electrumCandidates)
  for (const a of electrum.attempts) {
    info(`${a.error ? '·' : '✓'} ${a.candidate.host}:${a.candidate.port}  ${a.candidate.why}`)
  }
  if (!electrum.found) {
    console.log('')
    for (const line of remedyFor('indexer', remote).split('\n')) info(line)
    if (!DRY) {
      die('cannot install: without an indexer the receiver can never notice a payment')
    }
    warn('a real run would STOP here: no indexer means payments are never noticed')
  }
  const indexer = electrum.found ?? { host: '<none>', port: FULCRUM_PORT, why: 'not found' }
  info(`indexer: ${indexer.host}:${indexer.port}`)

  const soroban = await probeSoroban(sorobanCandidates)
  if (!soroban.found) {
    console.log('')
    for (const line of remedyFor('soroban', remote).split('\n')) info(line)
    if (!DRY) die('cannot install: without Soroban no customer can register')
    warn('a real run would STOP here: no Soroban means no customer can register')
  }
  const sorobanUrl = sorobanUrlOverride ?? (soroban.found ? sorobanUrlFor(soroban.found) : '<none>')
  info(`soroban: ${sorobanUrl}`)

  // Refuse before touching the system: on mainnet an indexer the operator does
  // not control would learn the entire customer list.
  try {
    assertIndexerAllowed(network, indexer.host, process.env.PAYNYM_BOT_ALLOW_REMOTE_INDEXER === 'yes')
  } catch (err) {
    die((err as Error).message)
  }
  if (isOnion(indexer.host)) {
    warn('the indexer is remote, so its operator sees every address this bot watches.')
    warn('acceptable for a testnet rehearsal; never for mainnet.')
  }

  // --- 6. Service account and files ----------------------------------------
  heading('Install')
  act(`create system user ${SERVICE_USER}`, () => {
    try {
      sh('id', [SERVICE_USER])
    } catch {
      sh('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', SERVICE_USER])
    }
  })

  act(`copy application to ${root}`, () => {
    mkdirSync(root, { recursive: true })
    if (has('rsync')) {
      sh('rsync', ['-a', '--delete', '--exclude', '.git', '--exclude', 'node_modules', `${REPO}/`, `${root}/`])
    } else {
      // rsync is not installed on a minimal Debian, and requiring it just to
      // copy a directory would be a poor reason to fail an install.
      sh('sh', ['-c', `cd ${JSON.stringify(REPO)} && tar --exclude=.git --exclude=node_modules -cf - . | tar -xf - -C ${JSON.stringify(root)}`])
    }
    // npm ci, not install: the committed lockfile is what makes the deployed
    // dependency set reproducible, which matters for something holding keys.
    sh('npm', ['ci', '--omit=dev', '--prefix', root])
  })

  act(`create ${dataDir} owned by ${SERVICE_USER}`, () => {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 })
    sh('chown', ['-R', `${SERVICE_USER}:${SERVICE_USER}`, dataDir])
    chmodSync(dataDir, 0o700)
  })

  // Prove the service account can actually write there, rather than finding out
  // at first start.
  act('verify the service account can write to the data directory', () => {
    const probe = join(dataDir, '.write-probe')
    sh('runuser', ['-u', SERVICE_USER, '--', 'touch', probe])
    sh('rm', ['-f', probe])
  })

  act('write the wallet and initial state', () => {
    writeFileSync(join(dataDir, 'seed'), `${mnemonic}\n`, { mode: 0o600 })
    saveState(join(dataDir, 'state.json'), newState(network, Date.now(), label || undefined))
    const written = [join(dataDir, 'seed'), join(dataDir, 'state.json')]
    if (passphrase.length > 0) {
      // 0600 beside the phrase, NOT in the unit file: units are world-readable
      // by default, and the phrase itself is not.
      writeFileSync(join(dataDir, 'passphrase'), `${passphrase}\n`, { mode: 0o600 })
      written.push(join(dataDir, 'passphrase'))
    }
    sh('chown', [`${SERVICE_USER}:${SERVICE_USER}`, ...written])
  })

  // --- 7. Tor ---------------------------------------------------------------
  heading('Hidden service')
  const existingTorrc = existsSync(TORRC) ? readFileSync(TORRC, 'utf8') : ''
  let mergedTorrc: string
  try {
    mergedTorrc = mergeTorrc(existingTorrc, {
      dir: TOR_SERVICE_DIR,
      virtualPort: 80,
      targetPort: httpPort,
    })
  } catch (err) {
    die((err as Error).message)
  }

  act(`add a hidden service to ${TORRC} (other services untouched)`, () => {
    writeFileSync(`${TORRC}.paynym-bot.bak`, existingTorrc)
    writeFileSync(TORRC, mergedTorrc)
  })
  act('restart tor', () => sh('systemctl', ['restart', 'tor']))

  let onion = '<pending>'
  if (!DRY) {
    const hostnameFile = join(TOR_SERVICE_DIR, 'hostname')
    for (let i = 0; i < 30; i++) {
      if (existsSync(hostnameFile)) {
        onion = readFileSync(hostnameFile, 'utf8').trim()
        break
      }
      await new Promise((r) => setTimeout(r, 1000))
    }
    if (onion === '<pending>') {
      warn(`tor has not written ${hostnameFile} yet — check: journalctl -u tor`)
    } else {
      info(`onion: ${onion}`)
    }
  }

  // --- 8. Service -----------------------------------------------------------
  heading('Service')
  const unit = readFileSync(join(REPO, 'scripts', 'paynym-bot.service'), 'utf8')
    .replaceAll('__SERVICE_USER__', SERVICE_USER)
    .replaceAll('__INSTALL_ROOT__', root)
    .replaceAll('__NODE_BIN__', flag('node-bin') ?? process.execPath)
    .replaceAll('__DATA_DIR__', dataDir)
    .replaceAll('__SOROBAN_URL__', sorobanUrl)
    .replaceAll('__ELECTRUM_HOST__', indexer.host)
    .replaceAll('__ELECTRUM_PORT__', String(indexer.port))
    .replaceAll('__HTTP_PORT__', String(httpPort))
    .replaceAll(
      '__ALLOW_REMOTE_INDEXER__',
      process.env.PAYNYM_BOT_ALLOW_REMOTE_INDEXER === 'yes' ? 'yes' : 'no',
    )

  act(`write ${UNIT}`, () => writeFileSync(UNIT, unit, { mode: 0o644 }))
  act('enable and start paynym-bot', () => {
    sh('systemctl', ['daemon-reload'])
    sh('systemctl', ['enable', '--now', 'paynym-bot.service'])
  })

  if (!DRY) {
    await new Promise((r) => setTimeout(r, 2000))
    const active = sh('systemctl', ['is-active', 'paynym-bot.service']).trim()
    if (active !== 'active') {
      warn(`service is "${active}" — inspect with: journalctl -u paynym-bot -n 50`)
    } else {
      info('service is running')
    }
  }

  // --- Done -----------------------------------------------------------------
  console.log('\n\x1b[1mInstalled.\x1b[0m\n')
  console.log(`   network:  ${network}`)
  console.log(`   onion:    http://${onion}/`)
  console.log(`   PayNym:   ${identity.paymentCode()}`)
  console.log(`   data:     ${dataDir}`)
  console.log('')
  console.log('   Back up the recovery phrase AND the data directory. Neither alone is')
  console.log('   enough to find money already received.')
  console.log('')
  console.log('   paynym-bot doctor    re-check the connection to your Dojo')
  console.log('   journalctl -u paynym-bot -f')
  console.log('')
} finally {
  rl.close()
}
