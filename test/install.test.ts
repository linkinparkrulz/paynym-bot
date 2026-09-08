// Deployment predicates that would otherwise only be discovered on a real box.

import { nodeIsReachableByService } from '../src/config.ts'

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

console.log('')
if (failures === 0) {
  console.log('PASS — installer refuses a Node the hardened service could not execute.')
} else {
  console.log(`FAIL — ${failures} installer check(s) failed.`)
  process.exit(1)
}
