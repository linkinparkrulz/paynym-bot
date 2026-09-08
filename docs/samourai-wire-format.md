# Samourai's Soroban wire format

Recovered by reading [`extlibj`](https://github.com/Archive-Samourai-Wallet/extlibj) and
[`soroban-client-java`](https://github.com/Archive-Samourai-Wallet/soroban-client-java),
and verified by compiling and running their own Java. Written down so nobody has to repeat
the archaeology.

Implemented in [`src/samourai.ts`](../src/samourai.ts); pinned in
[`test/samourai.test.ts`](../test/samourai.test.ts).

> Finding the source: the classes are under `extlibj/java/…`, **not** `src/main/java/…`,
> and `RpcDialog` is in `client/dialog/`, not `client/rpc/`. `extlibj`'s default branch is
> `feature/dexwp` — the slash breaks `raw.githubusercontent.com` URLs, so fetch by commit
> SHA or clone.

## Directory

`RpcDialog.encodeDirectory` — `hex(SHA256(utf8(name)))`.

A session is opened with `rpcSession.createRpcDialog(paymentCodePartner.toString())`, so
the name hashed is the **bare payment code**, with no prefix. We listen there as
`samouraiInboxName()` alongside our own prefixed directory.

## Entry

`RpcDialogEndpointWithSender.encryptTo` posts:

```json
{"sender": "<sender payment code, CLEARTEXT>", "payload": "<Z85(encrypted)>"}
```

Their own comment on that line reads `// wrap with clear sender`.

## Payload

`Bip47EncrypterImpl` → `CryptoUtil` → `ECDHKeySet`:

1. **ECDH, static-static.** Our notification key (payment-code child-0) private against the
   partner's notification key public. The JCA's `generateSecret()` returns the 32-byte X
   coordinate of the shared point.
2. **KDF.** `encryptionKey = SHA256(X ‖ 0x00)`, `hmacKey = SHA256(X ‖ 0x01)`.
3. **Cipher.** AES-256-CTR, no padding, random 16-byte IV.
4. **MAC.** HMAC-SHA512 over `IV ‖ ciphertext`, keyed with `hmacKey`.
5. **Framing.** `IV(16) ‖ HMAC(64) ‖ ciphertext` (`EncryptedMessage.serialize`).
6. **Encoding.** Z85, via `SorobanEncrypter`.

### Z85 is not quite the ZeroMQ spec

Reference Z85 requires a length divisible by four. `extlibj`'s `Z85.java` extends it with
its own partial-block handling — on the final short block it emits only the digits where
`j > padding`, dropping the least significant. Match *their* implementation, not the spec.

### A quirk to preserve, not fix

`CryptoUtil.encryptAES_CTR` calls `cipher.init(Cipher.DECRYPT_MODE, …)` inside the
**encrypt** path. This is harmless for CTR, where encryption and decryption are the same
keystream XOR, so it produces correct output — but it means any harness used to generate
test vectors must reproduce it as-is. "Correcting" it would still yield the same bytes
today, and would silently diverge if the mode ever changed.

## Signing

Separate from encryption, and also different from ours: Bitcoin signed-message format over
the notification-address key, verified against the notification **address**
(`MessageSignUtilGeneric`). Ours is raw DER over SHA256. Not currently implemented here.

## Why this is a compatibility option, not the default

The cleartext `sender` is structurally unavoidable: static-static ECDH means the receiver
must know which partner key to use *before* it can decrypt, so a stranger has to announce
themselves in the open.

For Cahoots that leaks nothing — the two parties already follow each other and are already
linked on-chain by notification transactions. For a merchant it is fatal: the inbox
directory is `SHA256(publishedPaymentCode)`, so anyone can list it and read the whole
customer list. That is exactly the linkage the notification transaction blinds, which
would leave us worse off than the mechanism this project removes.

So the bot **accepts** this format, and its storefront says plainly that paying from a
stock wallet publishes your payment code. Our own format
([`src/channel.ts`](../src/channel.ts)) uses an ephemeral key and stays the default.

## One thing the static-static scheme gets for free

Because forging a payload for someone else's payment code would require *their* private
notification key, a payload whose HMAC verifies could only have been produced by the holder
of the claimed payment code. **Successful decryption is itself proof of identity**, so
entries in this format need no inner signature.

Our own format has the opposite property — anyone holding our published payment code can
seal to us with an ephemeral key — which is precisely why that path additionally requires
the signed registration envelope.
