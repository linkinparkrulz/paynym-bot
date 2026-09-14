// The `paynym-bot` command itself.
//
// The CLI is a .ts file run through Node's type stripping, so it cannot simply
// be symlinked onto PATH: the interpreter needs flags. This generates the small
// shell wrapper that supplies them.
//
// It is written the same way ./torrc.ts writes its block — with a marker — and
// for the same reason. /usr/local/bin belongs to the operator, not to us. If
// something called `paynym-bot` is already there and we did not write it, that
// is a file with a history we know nothing about, and the right move is to stop
// and say so rather than to overwrite it.

/** Where the command lands. Present on every distribution we target. */
export const SHIM_PATH = '/usr/local/bin/paynym-bot'

/**
 * How we recognise our own wrapper on a later install or uninstall. Changing
 * this orphans every shim already written, so it is fixed.
 */
export const SHIM_MARKER = '# installed by paynym-bot install.sh'

export type ShimSpec = {
  /** The Node binary to run. Pin the SAME one the systemd unit pins. */
  nodeBin: string
  /** Install root holding bin/paynym-bot.ts. */
  root: string
  /** Data directory the CLI should read by default. */
  dataDir: string
}

/**
 * The wrapper script.
 *
 * `PAYNYM_BOT_DATA` is defaulted rather than forced, so an operator running a
 * second instance can still point the same command at another data directory
 * without editing this file.
 *
 * The Node binary is pinned instead of resolved through PATH at run time. The
 * installer has already refused a Node the hardened service could not execute
 * (see `nodeIsReachableByService`), and a CLI that silently ran on a different
 * runtime than the service — a newer nvm Node earlier in the operator's PATH,
 * say — would diagnose a deployment that is not the one running.
 */
export function shimScript(spec: ShimSpec): string {
  return [
    '#!/bin/sh',
    SHIM_MARKER,
    '# Delete this file to remove the command, or run ./uninstall.sh --apply.',
    `export PAYNYM_BOT_DATA="\${PAYNYM_BOT_DATA:-${spec.dataDir}}"`,
    `exec "${spec.nodeBin}" --experimental-strip-types --no-warnings \\`,
    `  "${spec.root}/bin/paynym-bot.ts" "$@"`,
    '',
  ].join('\n')
}

/** True if `contents` is a wrapper we wrote, and so ours to replace or delete. */
export function isOurShim(contents: string): boolean {
  return contents.includes(SHIM_MARKER)
}
