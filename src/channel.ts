// Channel encryption derived from BIP47 payment codes.
//
// This replaces the previous scheme, in which the receiver published an
// ephemeral NaCl box key to a Soroban directory and senders fetched it. That
// key was unauthenticated: anyone able to write to the directory could publish
// a competing key, and senders would encrypt their payment code to the
// attacker instead. Publishing a key at all was the mistake.
//
// The construction here mirrors BIP47's own notification transaction. On-chain,
// Alice reveals an ephemeral public key (her transaction input) in the clear and
// blinds the payload with ECDH against Bob's notification key; Bob recomputes
// the same secret from Alice's visible pubkey. We do exactly that off-chain:
//
//   sealed = <ephemeral pubkey, clear> ":" <secretbox(payload, ECDH(eph, B_0))>
//
// B_0 is the receiver's child-0 (notification) key, which is a pure function of
// the payment code the customer already has. There is nothing published, so
// there is nothing to substitute: an attacker who cannot compute B_0's private
// key cannot open the payload, and one who serves a different payment code is
// simply a different merchant, which is the onion's problem to attest, not the
// channel's.
//
// The cipher is deliberately isolated behind seal/open so it can be swapped for
// Samourai's exact wire format without disturbing the session logic above it.
// NOTE: this is NOT byte-compatible with Samourai's Bip47Encrypter — see
// ../README.md. It matches the shape, not the bytes.

import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import nacl from 'tweetnacl'
import { nodeFromPaymentCode } from './bip47.ts'
import { hex, unhex } from './soroban.ts'

/** The receiver's child-0 (notification) public key, from their payment code. */
export function notificationPubkey(paymentCode: string): Uint8Array {
  return nodeFromPaymentCode(paymentCode).deriveChild(0).publicKey!
}

/**
 * Symmetric key for a channel: SHA256 of the x-coordinate of the ECDH point.
 * getSharedSecret returns a compressed point, so bytes 1..33 are x.
 */
function channelKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = secp256k1.getSharedSecret(privateKey, publicKey, true)
  return sha256(shared.subarray(1, 33))
}

/**
 * Encrypt `plaintext` so only the holder of `receiverPaymentCode`'s child-0
 * private key can read it. Output is `ephemeralPubkeyHex:nonceAndBoxHex`.
 */
export function sealToPaymentCode(receiverPaymentCode: string, plaintext: string): string {
  const ephemeralPriv = secp256k1.utils.randomPrivateKey()
  const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, true)
  const key = channelKey(ephemeralPriv, notificationPubkey(receiverPaymentCode))

  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  const box = nacl.secretbox(new TextEncoder().encode(plaintext), nonce, key)
  const merged = new Uint8Array(nonce.length + box.length)
  merged.set(nonce)
  merged.set(box, nonce.length)
  return `${hex(ephemeralPub)}:${hex(merged)}`
}

/**
 * Decrypt a sealed payload with our own child-0 private key. Returns null on
 * any failure — malformed input, a point that is not on the curve, or a failed
 * Poly1305 tag — so a hostile inbox entry can never be distinguished from a
 * merely corrupt one, and never throws into the caller's drain loop.
 */
export function openWithIdentityKey(
  identityPrivateKey: Uint8Array,
  sealed: string,
): string | null {
  const sep = sealed.indexOf(':')
  if (sep < 0) return null
  try {
    const ephemeralPub = unhex(sealed.slice(0, sep))
    const bytes = unhex(sealed.slice(sep + 1))
    if (bytes.length <= nacl.secretbox.nonceLength) return null

    const key = channelKey(identityPrivateKey, ephemeralPub)
    const nonce = bytes.slice(0, nacl.secretbox.nonceLength)
    const box = bytes.slice(nacl.secretbox.nonceLength)
    const opened = nacl.secretbox.open(box, nonce, key)
    return opened ? new TextDecoder().decode(opened) : null
  } catch {
    return null
  }
}
