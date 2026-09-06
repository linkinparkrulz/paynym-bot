// Editing a shared /etc/tor/torrc.
//
// This is the code most able to damage something outside the project: an
// operator running beside a Dojo already has hidden services here, and a bad
// edit takes Tor down for all of them. These tests exist to make sure other
// people's stanzas survive us.

import { BEGIN_MARKER, END_MARKER, hasUnmanagedService, mergeTorrc, removeBlock } from '../src/torrc.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}
function throws(name: string, fn: () => unknown, expect?: string): void {
  try {
    fn()
    assert(name, false)
  } catch (e) {
    assert(name, expect ? (e as Error).message.includes(expect) : true)
  }
}

const SVC = { dir: '/var/lib/tor/paynym-bot', virtualPort: 80, targetPort: 8462 }

// A realistic torrc: a Dojo's own hidden services, plus operator settings.
const EXISTING = `SocksPort 9050
ControlPort 9051

# Dojo
HiddenServiceDir /var/lib/tor/dojo-api/
HiddenServicePort 80 172.29.1.3:80

HiddenServiceDir /var/lib/tor/dojo-soroban/
HiddenServicePort 80 172.29.1.9:4242

Log notice file /var/log/tor/notices.log`

// --- adding ------------------------------------------------------------------
const merged = mergeTorrc(EXISTING, SVC)
assert('keeps SocksPort', merged.includes('SocksPort 9050'))
assert('keeps the dojo api service', merged.includes('/var/lib/tor/dojo-api/'))
assert('keeps the dojo soroban service', merged.includes('/var/lib/tor/dojo-soroban/'))
assert('keeps the trailing log line', merged.includes('Log notice file'))
assert('adds our service dir', merged.includes('HiddenServiceDir /var/lib/tor/paynym-bot'))
assert('maps the onion to our local port', merged.includes('HiddenServicePort 80 127.0.0.1:8462'))
assert('wraps our block in markers',
  merged.includes(BEGIN_MARKER) && merged.includes(END_MARKER))
assert('leaves every original line intact',
  EXISTING.split('\n').filter((l) => l.trim()).every((l) => merged.includes(l)))

// --- idempotence -------------------------------------------------------------
assert('merging twice changes nothing', mergeTorrc(merged, SVC) === merged)
assert('merging three times changes nothing', mergeTorrc(mergeTorrc(merged, SVC), SVC) === merged)
assert('only one block after repeats',
  mergeTorrc(merged, SVC).split(BEGIN_MARKER).length - 1 === 1)

// --- updating ----------------------------------------------------------------
const moved = mergeTorrc(merged, { ...SVC, targetPort: 9999 })
assert('updates the port in place', moved.includes('127.0.0.1:9999'))
assert('drops the old port', !moved.includes('127.0.0.1:8462'))
assert('still only one block', moved.split(BEGIN_MARKER).length - 1 === 1)
assert('other services survive an update', moved.includes('/var/lib/tor/dojo-api/'))

// --- empty and whitespace-only files -----------------------------------------
assert('works on an empty torrc', mergeTorrc('', SVC).includes('HiddenServiceDir'))
assert('does not lead with blank lines', !mergeTorrc('', SVC).startsWith('\n'))
assert('works on a whitespace-only torrc', mergeTorrc('\n\n  \n', SVC).includes(BEGIN_MARKER))

// --- refusing to take over someone else's stanza -----------------------------
const conflicting = `HiddenServiceDir /var/lib/tor/paynym-bot/
HiddenServicePort 80 127.0.0.1:1234`
assert('detects an unmanaged stanza for our dir', hasUnmanagedService(conflicting, SVC.dir))
assert('trailing slashes do not hide a conflict',
  hasUnmanagedService('HiddenServiceDir /var/lib/tor/paynym-bot', SVC.dir))
throws('refuses to duplicate or take it over', () => mergeTorrc(conflicting, SVC), 'outside the paynym-bot')
assert('our own block is not a conflict', !hasUnmanagedService(merged, SVC.dir))
assert('another service is not a conflict', !hasUnmanagedService(EXISTING, SVC.dir))

// --- removal (uninstall) ------------------------------------------------------
const removed = removeBlock(merged)
assert('removal drops our service dir', !removed.includes('/var/lib/tor/paynym-bot'))
assert('removal drops both markers',
  !removed.includes(BEGIN_MARKER) && !removed.includes(END_MARKER))
assert('removal keeps the dojo services',
  removed.includes('/var/lib/tor/dojo-api/') && removed.includes('/var/lib/tor/dojo-soroban/'))
assert('removal keeps every original line',
  EXISTING.split('\n').filter((l) => l.trim()).every((l) => removed.includes(l)))
assert('removal is a no-op when we were never there', removeBlock(EXISTING).trim() === EXISTING.trim())
assert('remove after merge round-trips', removeBlock(mergeTorrc(EXISTING, SVC)).trim() === EXISTING.trim())

console.log('')
if (failures === 0) {
  console.log("PASS — torrc merging leaves other hidden services alone.")
} else {
  console.log(`FAIL — ${failures} torrc check(s) failed.`)
  process.exit(1)
}
