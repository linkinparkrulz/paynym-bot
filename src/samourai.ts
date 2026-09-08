// Samourai's Soroban wire format, reimplemented to match byte for byte.
//
// Recovered by reading Archive-Samourai-Wallet/extlibj and soroban-client-java:
// Bip47EncrypterImpl -> CryptoUtil -> ECDHKeySet, and
// RpcDialogEndpointWithSender for the envelope. This exists so an unmodified
// Samourai/Ashigaru wallet can pay the bot.
//
// READ THIS BEFORE USING IT. The envelope carries the sender's payment code in
// CLEARTEXT — their own source comments it "wrap with clear sender". That is
// structurally unavoidable here: the payload is encrypted under a STATIC-STATIC
// ECDH between the two notification keys, so the receiver must know which
// partner key to use before it can decrypt anything, and a stranger must
// therefore announce themselves in the open.
//
// For Samourai that leaks nothing: Cahoots happens between people who already
// follow each other and are already linked on-chain by notification
// transactions. For a merchant it is the whole ballgame — the inbox directory
// is SHA256 of the merchant's published payment code, so anyone can list it and
// read the entire customer list. That is exactly the linkage the notification
// transaction blinds.
//
// So this format is offered for COMPATIBILITY, never as the default. Our own
// format (./channel.ts) uses an ephemeral key and keeps the payment code
// confidential; see Registrar.ingest, which accepts both and prefers ours.

import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { notificationPubkey } from './channel.ts'

// --- Z85 --------------------------------------------------------------------
// ZeroMQ base85, but matching THEIR implementation rather than the spec: the
// reference Z85 requires a length divisible by 4, and extlibj extends it with
// its own partial-block handling. Matching the spec here would be wrong.

const ENCODERS =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'

const DECODERS = [
  0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 0x4b, 0x4c, 0x46, 0x41, 0x00, 0x3f, 0x3e, 0x45,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4a, 0x47,
  0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
  0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x4d, 0x00, 0x4e, 0x43, 0x00,
  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x4f, 0x00, 0x50, 0x00, 0x00,
]

export function z85Encode(bytes: Uint8Array): string {
  const remainder = bytes.length % 4
  const padding = remainder > 0 ? 4 - remainder : 0
  let out = ''
  let value = 0
  for (let i = 0; i < bytes.length + padding; i++) {
    const isPadding = i >= bytes.length
    value = value * 256 + (isPadding ? 0 : bytes[i])
    if ((i + 1) % 4 === 0) {
      let div = 85 ** 4
      for (let j = 5; j > 0; j--) {
        // On the final partial block the least-significant digits are dropped.
        if (!isPadding || j > padding) out += ENCODERS[Math.floor(value / div) % 85]
        div /= 85
      }
      value = 0
    }
  }
  return out
}

export function z85Decode(text: string): Uint8Array {
  const remainder = text.length % 5
  const padding = 5 - (remainder === 0 ? 5 : remainder)
  let s = text
  for (let p = 0; p < padding; p++) s += ENCODERS[ENCODERS.length - 1]

  const out = new Uint8Array((s.length * 4) / 5 - padding)
  let index = 0
  let value = 0
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i) - 32
    if (code < 0 || code >= DECODERS.length) throw new Error('invalid Z85 character')
    value = value * 85 + DECODERS[code]
    if ((i + 1) % 5 === 0) {
      let div = 256 ** 3
      while (div >= 1) {
        if (index < out.length) out[index++] = Math.floor(value / div) % 256
        div /= 256
      }
      value = 0
    }
  }
  return out
}

// --- The ECDH key set -------------------------------------------------------

const IV_LENGTH = 16
const HMAC_LENGTH = 64

export type EcdhKeySet = { encryptionKey: Uint8Array; hmacKey: Uint8Array }

/**
 * Static-static ECDH between our notification key and the partner's, then the
 * two derived keys. `generateSecret()` in the JCA yields the 32-byte X
 * coordinate of the shared point, which is what noble's compressed output
 * carries in bytes 1..33.
 */
export function ecdhKeySet(ourPrivateKey: Uint8Array, theirPublicKey: Uint8Array): EcdhKeySet {
  const shared = secp256k1.getSharedSecret(ourPrivateKey, theirPublicKey, true)
  return keySetFromMaster(shared.subarray(1, 33))
}

/** The KDF alone, split out so it can be checked against the Java directly. */
export function keySetFromMaster(master: Uint8Array): EcdhKeySet {
  const withByte = (b: number) => {
    const buf = new Uint8Array(master.length + 1)
    buf.set(master)
    buf[master.length] = b
    return sha256(buf)
  }
  return { encryptionKey: withByte(0x00), hmacKey: withByte(0x01) }
}

function mac(keys: EcdhKeySet, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return Uint8Array.from(
    createHmac('sha512', keys.hmacKey).update(iv).update(ciphertext).digest(),
  )
}

/** Encrypt to `IV(16) ‖ HMAC-SHA512(64) ‖ ciphertext`, AES-256-CTR. */
export function samouraiEncrypt(
  plaintext: string,
  keys: EcdhKeySet,
  // Injectable only so tests can pin a vector against the reference
  // implementation. Never pass this in production.
  fixedIv?: Uint8Array,
): Uint8Array {
  const iv = fixedIv ?? randomBytes(IV_LENGTH)
  const cipher = createCipheriv('aes-256-ctr', keys.encryptionKey, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const out = new Uint8Array(IV_LENGTH + HMAC_LENGTH + ciphertext.length)
  out.set(iv, 0)
  out.set(mac(keys, iv, ciphertext), IV_LENGTH)
  out.set(ciphertext, IV_LENGTH + HMAC_LENGTH)
  return out
}

/** Decrypt the above. Returns null on any failure, including a bad MAC. */
export function samouraiDecrypt(encrypted: Uint8Array, keys: EcdhKeySet): string | null {
  if (encrypted.length < IV_LENGTH + HMAC_LENGTH) return null
  const iv = encrypted.subarray(0, IV_LENGTH)
  const claimed = encrypted.subarray(IV_LENGTH, IV_LENGTH + HMAC_LENGTH)
  const ciphertext = encrypted.subarray(IV_LENGTH + HMAC_LENGTH)

  // Constant-time, and checked BEFORE decrypting: CTR mode is malleable, so an
  // unauthenticated decrypt would hand attacker-chosen plaintext upstream.
  const expected = mac(keys, iv, ciphertext)
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(claimed))) return null

  const decipher = createDecipheriv('aes-256-ctr', keys.encryptionKey, iv)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
}

// --- The envelope -----------------------------------------------------------

export type SamouraiEnvelope = { sender: string; payload: string }

/** True if `entry` looks like `{"sender":…,"payload":…}`. */
export function parseSamouraiEnvelope(entry: string): SamouraiEnvelope | null {
  const trimmed = entry.trim()
  if (!trimmed.startsWith('{')) return null
  try {
    const obj = JSON.parse(trimmed)
    if (typeof obj?.sender !== 'string' || typeof obj?.payload !== 'string') return null
    if (obj.sender.length === 0 || obj.payload.length === 0) return null
    return { sender: obj.sender, payload: obj.payload }
  } catch {
    return null
  }
}

/**
 * Build an entry a Samourai client would accept. The sender's payment code is
 * necessarily in the clear — see the note at the top of this file.
 */
export function sealSamourai(
  senderPrivateKey: Uint8Array,
  senderPaymentCode: string,
  receiverPaymentCode: string,
  plaintext: string,
): string {
  const keys = ecdhKeySet(senderPrivateKey, notificationPubkey(receiverPaymentCode))
  return JSON.stringify({
    sender: senderPaymentCode,
    payload: z85Encode(samouraiEncrypt(plaintext, keys)),
  })
}

/**
 * Open a Samourai entry. Returns the plaintext and the (cleartext, therefore
 * unproven) sender code — authenticity is established by the signed envelope
 * inside, not by this transport.
 */
export function openSamourai(
  ourPrivateKey: Uint8Array,
  entry: string,
): { sender: string; plaintext: string } | null {
  const envelope = parseSamouraiEnvelope(entry)
  if (!envelope) return null
  try {
    const keys = ecdhKeySet(ourPrivateKey, notificationPubkey(envelope.sender))
    const plaintext = samouraiDecrypt(z85Decode(envelope.payload), keys)
    return plaintext === null ? null : { sender: envelope.sender, plaintext }
  } catch {
    return null
  }
}
