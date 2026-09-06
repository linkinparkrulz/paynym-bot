// A PayNym identity: everything derivable from a single BIP32 seed.
//
// This is the load-bearing key material for the always-online receiver. Note
// that the *receive keys* cannot be reconstructed from the seed alone — they
// also require the set of sender payment codes you have registered. Back up the
// registry (see register.ts) alongside the seed.

import { HDKey } from '@scure/bip32'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import {
  MAINNET,
  encodePaymentCode,
  p2pkhAddress,
  receiveAddress,
  receivePrivateKey,
  sendAddress,
} from './bip47.ts'
import type { Network } from './bip47.ts'

function toHex(u8: Uint8Array): string {
  return Buffer.from(u8).toString('hex')
}

export class PaynymIdentity {
  readonly network: Network
  readonly account: HDKey

  private constructor(account: HDKey, network: Network) {
    this.account = account
    this.network = network
  }

  /** Build an identity from a raw BIP32 seed. */
  static fromSeed(seed: Uint8Array, network: Network = MAINNET, identity = 0): PaynymIdentity {
    const master = HDKey.fromMasterSeed(seed)
    const account = master.derive(`m/47'/${network.coinType}'/${identity}'`)
    return new PaynymIdentity(account, network)
  }

  /** Our payment code (the "PM8T..." string) to hand to senders. */
  paymentCode(): string {
    return encodePaymentCode(this.account.publicKey!, this.account.chainCode!)
  }

  /**
   * Our notification address (P2PKH of the account's child-0 pubkey).
   * We do NOT require anyone to pay this — it exists so unmodified BIP47
   * wallets (Mode A) can still reach us. Notification-less senders skip it.
   */
  notificationAddress(): string {
    return p2pkhAddress(this.account.deriveChild(0).publicKey!, this.network)
  }

  /**
   * The secp256k1 key at child index 0. This is our stable BIP47 identity key;
   * we use it to sign registration messages so a receiver can verify that a
   * submitted payment code is controlled by whoever sent the Soroban message.
   */
  identityPublicKey(): string {
    return toHex(this.account.deriveChild(0).publicKey!)
  }
  identityPrivateKey(): Uint8Array {
    return this.account.deriveChild(0).privateKey!
  }

  /** Sign a message with the identity key (compact DER hex over SHA256(msg)). */
  signIdentity(message: Uint8Array): string {
    const digest = sha256(message)
    const sig = secp256k1.sign(digest, this.identityPrivateKey())
    return sig.toDERHex()
  }

  /** Receiver: address to receive sender's `index`-th payment. */
  receiveAddress(senderPaymentCode: string, index: number): string {
    return receiveAddress(this.account, senderPaymentCode, index, this.network)
  }

  /** Receiver: spend key (hex) for `receiveAddress(senderPaymentCode, index)`. */
  receivePrivateKey(senderPaymentCode: string, index: number): string {
    return receivePrivateKey(this.account, senderPaymentCode, index, this.network)
  }

  /** Sender: address to pay receiver's `index`-th payment. */
  sendAddress(receiverPaymentCode: string, index: number): string {
    return sendAddress(this.account, receiverPaymentCode, index, this.network)
  }
}

/** Verify a registration signature against the payment code's own identity key. */
export function verifyIdentitySignature(
  identityPublicKeyHex: string,
  message: Uint8Array,
  derSignatureHex: string,
): boolean {
  try {
    const digest = sha256(message)
    // Parse the DER explicitly and hand verify() a fixed 64-byte compact
    // signature. Passing the DER hex straight through relied on verify()
    // guessing the encoding, which is both untyped and ambiguous.
    const der = Uint8Array.from(Buffer.from(derSignatureHex, 'hex'))
    const compact = secp256k1.Signature.fromDER(der).toCompactRawBytes()
    return secp256k1.verify(compact, digest, Uint8Array.from(Buffer.from(identityPublicKeyHex, 'hex')))
  } catch {
    return false
  }
}
