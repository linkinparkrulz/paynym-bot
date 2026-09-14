// paynym-bot uninstaller.
//
// Dry run unless --apply. The destructive options are separate and explicit,
// because the two things this can delete are not recoverable:
//
//   the data directory  — holds the recovery phrase AND the registered customer
//     payment codes. A BIP47 receive address depends on both parties' codes, so
//     deleting it makes money already received undiscoverable even if the
//     phrase was written down.
//   the onion key       — the merchant's published address. Deleting it means
//     every customer who saved that address can no longer reach the shop.
//
// Anything else in torrc belongs to somebody else and is left exactly as it is.

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { removeBlock } from '../src/torrc.ts'
import { SHIM_PATH, isOurShim } from '../src/shim.ts'

const args = new Set(process.argv.slice(2))
const APPLY = args.has('--apply')
const PURGE_DATA = args.has('--purge-data')
const PURGE_ONION = args.has('--purge-onion')

const UNIT = '/etc/systemd/system/paynym-bot.service'
const TORRC = '/etc/tor/torrc'
const TOR_SERVICE_DIR = '/var/lib/tor/paynym-bot'
const SERVICE_USER = 'paynym-bot'
const DEFAULT_DATA = '/var/lib/paynym-bot'

const info = (t: string) => console.log(`   ${t}`)
const warn = (t: string) => console.log(`   \x1b[33m! ${t}\x1b[0m`)

function act(description: string, fn: () => void): void {
  if (!APPLY) {
    console.log(`   \x1b[2mwould:\x1b[0m ${description}`)
    return
  }
  info(description)
  try {
    fn()
  } catch (err) {
    warn(`${description} — failed: ${(err as Error).message}`)
  }
}

const sh = (cmd: string, a: string[]) =>
  execFileSync(cmd, a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })

console.log('\n\x1b[1mpaynym-bot uninstall\x1b[0m')
if (!APPLY) console.log('\x1b[2m(dry run — nothing will be changed; pass --apply to act)\x1b[0m')

// --- stop serving -----------------------------------------------------------
console.log('\n\x1b[1mService\x1b[0m')
if (existsSync(UNIT)) {
  act('stop and disable paynym-bot.service', () => {
    try {
      sh('systemctl', ['disable', '--now', 'paynym-bot.service'])
    } catch {
      /* already stopped */
    }
  })
  act(`remove ${UNIT}`, () => {
    rmSync(UNIT, { force: true })
    sh('systemctl', ['daemon-reload'])
  })
} else {
  info(`${UNIT} is not present`)
}

// The command wrapper. Only ours to delete: /usr/local/bin belongs to the
// operator, and something else called paynym-bot has a history we know nothing
// about.
if (existsSync(SHIM_PATH)) {
  if (isOurShim(readFileSync(SHIM_PATH, 'utf8'))) {
    act(`remove the paynym-bot command at ${SHIM_PATH}`, () => rmSync(SHIM_PATH, { force: true }))
  } else {
    warn(`${SHIM_PATH} was not written by us — leaving it alone`)
  }
} else {
  info(`${SHIM_PATH} is not present`)
}

// --- torrc ------------------------------------------------------------------
console.log('\n\x1b[1mHidden service\x1b[0m')
if (existsSync(TORRC)) {
  const current = readFileSync(TORRC, 'utf8')
  const stripped = removeBlock(current)
  if (stripped.trim() === current.trim()) {
    info('torrc has no paynym-bot block')
  } else {
    act('remove our block from torrc (every other hidden service is left alone)', () => {
      writeFileSync(`${TORRC}.paynym-bot.bak`, current)
      writeFileSync(TORRC, stripped)
      try {
        sh('systemctl', ['restart', 'tor'])
      } catch {
        warn('could not restart tor; do it yourself when convenient')
      }
    })
  }
}

if (PURGE_ONION) {
  if (existsSync(TOR_SERVICE_DIR)) {
    warn('deleting the onion key: customers who saved that address lose the shop forever')
    act(`delete ${TOR_SERVICE_DIR}`, () => rmSync(TOR_SERVICE_DIR, { recursive: true, force: true }))
  }
} else if (existsSync(TOR_SERVICE_DIR)) {
  info(`keeping the onion key at ${TOR_SERVICE_DIR} (use --purge-onion to delete)`)
}

// --- data -------------------------------------------------------------------
console.log('\n\x1b[1mWallet and data\x1b[0m')
const dataDir = process.env.PAYNYM_BOT_DATA ?? DEFAULT_DATA
if (existsSync(dataDir)) {
  if (PURGE_DATA) {
    warn('deleting the data directory. This removes the recovery phrase AND the')
    warn('registered customer payment codes. A BIP47 receive address depends on both')
    warn('parties\' codes, so money already received becomes undiscoverable — the')
    warn('phrase alone will NOT recover it. Make sure you have swept the balance.')
    act(`delete ${dataDir}`, () => rmSync(dataDir, { recursive: true, force: true }))
  } else {
    info(`keeping ${dataDir} (use --purge-data to delete)`)
    info('it holds the recovery phrase and the customer payment codes')
  }
} else {
  info(`${dataDir} is not present`)
}

// --- account ----------------------------------------------------------------
if (PURGE_DATA) {
  act(`remove the ${SERVICE_USER} system user`, () => {
    try {
      sh('userdel', [SERVICE_USER])
    } catch {
      /* absent, or still owns files elsewhere */
    }
  })
}

console.log('')
if (!APPLY) {
  console.log('   Nothing was changed. Re-run with --apply to carry this out.\n')
} else {
  console.log('   Done. The application directory (/opt/paynym-bot by default) was left in')
  console.log('   place; remove it yourself if you want it gone.\n')
}
