// Deployment predicates that would otherwise only be discovered on a real box.

import { nodeIsReachableByService } from '../src/config.ts'
import { isOurShim, shimScript } from '../src/shim.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

// The unit sets ProtectHome=yes, so anything under a home directory is
// invisible to the service no matter how correct the path looks.
assert('nvm Node is rejected',
  !nodeIsReachableByService('/home/kaito/.nvm/versions/node/v22.11.0/bin/node'))
assert('root-owned nvm Node is rejected',
  !nodeIsReachableByService('/root/.nvm/versions/node/v22.11.0/bin/node'))
assert('~/.local Node is rejected', !nodeIsReachableByService('/home/kaito/.local/bin/node'))
assert('/run/user is rejected', !nodeIsReachableByService('/run/user/1000/node'))

assert('NodeSource /usr/bin is accepted', nodeIsReachableByService('/usr/bin/node'))
assert('/usr/local/bin is accepted', nodeIsReachableByService('/usr/local/bin/node'))
assert('/opt is accepted', nodeIsReachableByService('/opt/node22/bin/node'))
assert('/snap is accepted', nodeIsReachableByService('/snap/bin/node'))
// Names that merely start with the same letters must not be caught.
assert('/homebrew-ish paths are not confused', nodeIsReachableByService('/homelab/bin/node'))
assert('/rootfs is not confused', nodeIsReachableByService('/rootfs/usr/bin/node'))

// --- the `paynym-bot` command ------------------------------------------------
//
// The CLI is a .ts file run through Node's type stripping, so it cannot be
// symlinked onto PATH — the interpreter needs flags. These pin the wrapper that
// supplies them, and above all that it never overwrites a file it did not
// write: /usr/local/bin belongs to the operator.

const shim = shimScript({
  nodeBin: '/usr/bin/node',
  root: '/opt/paynym-bot',
  dataDir: '/var/lib/paynym-bot',
})

assert('the shim is a shell script', shim.startsWith('#!/bin/sh\n'))
assert('it carries the flags the CLI cannot run without', shim.includes('--experimental-strip-types'))
assert('it execs the CLI entrypoint', shim.includes('"/opt/paynym-bot/bin/paynym-bot.ts" "$@"'))
assert('it forwards arguments', shim.includes('"$@"'))
assert(
  'it pins the SAME node the unit pins, not whatever PATH offers',
  shim.includes('exec "/usr/bin/node"') && !shim.includes('command -v node'),
)
assert(
  'it defaults the data directory without forcing it',
  shim.includes('PAYNYM_BOT_DATA="${PAYNYM_BOT_DATA:-/var/lib/paynym-bot}"'),
)

// Round trip: what we write, we must later recognise as ours to remove.
assert('our own shim is recognised', isOurShim(shim))
assert('a foreign script is not claimed', !isOurShim('#!/bin/sh\nexec /usr/bin/something "$@"\n'))
assert('an empty file is not claimed', !isOurShim(''))
assert(
  'a script that merely mentions the name is not claimed',
  !isOurShim('#!/bin/sh\n# my own paynym-bot helper\nexec ssh shop paynym-bot "$@"\n'),
)

// Paths with spaces must survive: the operator chooses the install root.
const spaced = shimScript({
  nodeBin: '/opt/node 22/bin/node',
  root: '/opt/pay nym',
  dataDir: '/var/lib/pay nym',
})
assert('a quoted node path survives spaces', spaced.includes('exec "/opt/node 22/bin/node"'))
assert('a quoted script path survives spaces', spaced.includes('"/opt/pay nym/bin/paynym-bot.ts"'))

console.log('')
if (failures === 0) {
  console.log('PASS — installer refuses a Node the hardened service could not execute.')
} else {
  console.log(`FAIL — ${failures} installer check(s) failed.`)
  process.exit(1)
}
