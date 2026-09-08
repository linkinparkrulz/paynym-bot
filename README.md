# paynym-bot — take BIP47 payments without a notification transaction

A BIP47 payment to a **new** counterparty costs two transactions: a notification
transaction to connect, then the real payment. Between regulars that cost amortises
over many payments and nobody minds. **For a merchant it never amortises** — every
customer is a first payment — so the notification transaction is pure overhead on
every one-time payer, and the customer is the one who pays it.

This is an always-online receiver that removes it. It runs beside a
[Dojo](https://github.com/Dojo-Open-Source-Project/samourai-dojo), publishes an onion
page showing its PayNym, and trades the secrets needed to derive a receive address with
the customer over [Soroban](https://github.com/Archive-Samourai-Wallet/soroban) instead
of over the chain. The customer pays once.

The bot **derives and watches** receive addresses. It does not spend.

## Install

On a Debian 12 / Ubuntu 24.04 box that already runs a Dojo:

```bash
git clone https://github.com/linkinparkrulz/paynym-bot && cd paynym-bot
./install.sh --dry-run     # see exactly what it would do, change nothing
./install.sh               # guided install
```

The installer asks where to install, **which network** (permanent — see below), a shop
name, and whether to generate a recovery phrase or import one you already have. It then
finds your Dojo's indexer and Soroban, creates a service account, adds a Tor hidden
service **without disturbing any other service in your torrc**, and installs a hardened
systemd unit.

It **stops before installing anything** if it cannot reach your Dojo, and tells you how
to fix it — a receiver that cannot see the chain can never notice a payment. Re-run that
diagnosis any time with `paynym-bot doctor`.

Removal is a dry run unless you ask for it:

```bash
./uninstall.sh                                   # show the plan
sudo ./uninstall.sh --apply                      # stop serving, keep wallet and data
sudo ./uninstall.sh --apply --purge-data         # also delete the wallet and customers
```

## Commands

```
paynym-bot init --network testnet   # choose the network once; it is permanent
paynym-bot start                    # storefront + listen for customers + scan for payments
paynym-bot status                   # network, PayNym, what is being watched
paynym-bot serve                    # storefront only, no daemon
paynym-bot doctor                   # find the Dojo services, or explain why not
```

`init` generates a **12-word BIP39 recovery phrase** and shows it once, or imports one you
already have (`--mnemonic "…"`), so the bot can run on a PayNym you already own.

> **Back up the phrase *and* `state.json`.** The phrase alone is not a complete backup. A
> BIP47 receive address is a function of *both* parties' payment codes, so without the
> registered customer codes in the state file, money already received cannot be found.
> This is inherent to BIP47, not a choice made here.

## Why this works (and it isn't a hack)

A BIP47 receive address is a pure function of the two parties' payment codes.
Nothing in the derivation references a txid, an outpoint, or any on-chain data
— verify this in [`src/bip47.ts`](src/bip47.ts): it never sees the chain.

The notification transaction is a **mailbox for a recipient who might not be there**.
Alice wants to pay Bob; Bob may be running nothing at all, so Alice needs somewhere to
leave her payment code that will still be there whenever Bob next appears. The chain
supplies that: always available, infinite retention, no liveness required.

Guarantee presence and the requirement evaporates. That is why this is a *bot* — the
always-online property is the premise of the construction, not an operational detail
of it. Nothing weaker replaces the mailbox; the need for one is removed.

The resulting on-chain payment is a plain P2PKH send, byte-for-byte identical to any
other BIP47 payment. The BIP47 spec even reserves a features bit for non-chain
notification, so this is anticipated, not worked around.

**What it concedes.** The chain needs no liveness from either party and cannot be
censored; this needs the merchant online and reachable. For a merchant that is a
property they already need. **Both ends must also run notification-skipping code** — a
stock wallet only looks for your addresses once it has seen a notification, so it would
never find these.

## The derivation (the load-bearing math)

For a payment from sender to receiver at index `i`:

```
S_i = a_0 · B_i = b_i · A_0      (ECDH; symmetric — each side computes it from
                                  the other's payment code alone)
s_i = SHA256(S_i.x)              (32-byte big-endian x-coordinate; NOT HMAC)
addr_i = P2PKH(B_i + s_i·G)
```

where `a_0` / `A_0` are the **sender's child-0** key (`m/47'/0'/0'/0`, the
notification key) and `b_i` / `B_i` are the **receiver's child-i** key. The
sender fixes its index at 0; the receiver varies its own index `i`.

Two mistakes to avoid, both of which the vectors catch:

- The tweak is `SHA256(S.x)`, applied additively. There is **no HMAC** in the
  address tweak (that's BIP32 CKD logic, which does not belong here).
- The sender uses its key at **child index 0**, not the account node key. Those
  are different keys; using the account node reproduces neither the vectors nor
  the receiver's address.

Verified against the official BIP47 test vectors (Alice & Bob) — payment codes,
notification address, and all 10 receive addresses reproduce, and the sender's
computed pay address equals the receiver's watch address for every index:

```
npm install
npm test          # runs the vector gate AND the offline protocol test
```

Do not trust anything downstream until `npm run vectors` prints `PASS`.

## How Soroban carries the payment code

Grounded in Soroban's wire protocol (`services/directory.go`, `internal/common/ttl.go`
and the reference clients in the [Soroban repo](https://github.com/Archive-Samourai-Wallet/soroban)):

- JSON-RPC 2.0 over HTTP POST to a node's `/rpc`. Methods: `directory.List` /
  `directory.Add` / `directory.Remove`.
- A "directory" is just a key string, addressed by its **SHA256 hex** so the node never
  sees the readable name.
- Entries are opaque strings with a TTL by `Mode`: `fast`=15s, `short`=1m, `long`=5m,
  `default`=3m (node caps at 15m).

In a Dojo-side deployment Soroban sits on the same host, so the bot reaches it over
loopback and needs no SOCKS client. Tor is `torrc` configuration for the hidden service
the bot *exposes*.

### Registration ([`src/register.ts`](src/register.ts))

1. The customer reads the merchant's payment code from the onion page.
2. That single value yields both the inbox directory to post to and the key to encrypt
   under. The customer seals a signed envelope and `Add`s it. No transaction is broadcast.
3. The merchant drains the inbox, decrypts, verifies, and records the customer.
4. From then on the merchant watches `receiveAddress(customerCode, i…i+gap)` and the
   customer pays the identical `sendAddress(merchantCode, i)`.

There is **no rendezvous key and no key exchange**. An earlier design had the merchant
publish an ephemeral NaCl box key for customers to fetch; that key was unauthenticated,
so anyone able to write to the directory could publish a competing one and harvest
customers' payment codes in the clear. Publishing a key at all was the mistake.

### The channel ([`src/channel.ts`](src/channel.ts))

Confidentiality mirrors BIP47's own notification transaction. On-chain, Alice reveals an
ephemeral public key in the clear and blinds the payload with ECDH against Bob's
notification key. We do the same off-chain:

```
sealed = <ephemeral pubkey, clear> ":" secretbox(payload, SHA256(ECDH(eph, B_0).x))
```

`B_0` is the merchant's child-0 key — a pure function of the payment code the customer
already holds. Nothing is published, so there is nothing to substitute.

### Authenticity is app-layer, not transport

Decrypting proves only that the sender could encrypt to us, which anyone holding our
public payment code can do. So the envelope is **signed with the payment code's own
identity key** (secp256k1 child-0) and verified against the pubkey embedded in the
submitted code. The signed message names **both** parties, so an envelope addressed to
one merchant cannot be replayed into another's inbox. `test/protocol.test.ts` proves
both the forged-signature and wrong-merchant cases are rejected.

### Stock wallets: compatible, with a disclosed cost

The bot also speaks Samourai's own Soroban wire format, so an unmodified
Samourai/Ashigaru wallet can reach it. The format was recovered from their source and
verified byte-for-byte against their compiled Java — see
[docs/samourai-wire-format.md](docs/samourai-wire-format.md).

**It is not the default, for a reason.** Their envelope carries the sender's payment code
in cleartext, which is unavoidable given its static-static ECDH: the receiver must know
which partner key to use before it can decrypt. For Cahoots between parties already linked
on-chain that leaks nothing. For a merchant it publishes the entire customer list to
anyone who can read the PayNym and list the directory — the very linkage the notification
transaction blinds.

So the bot accepts both, prefers its own, and **the storefront tells the customer which
choice they are making** before they pay.

## Module map

| File | Role |
|------|------|
| `src/bip47.ts` | Derivation core: payment codes, notification address, `receiveAddress` / `sendAddress` / `receivePrivateKey`. Verified against the official vectors, network-independent. |
| `src/identity.ts` | `PaynymIdentity` — seed → account, payment code, identity signing. |
| `src/channel.ts` | Our channel encryption: ephemeral key, payment code stays confidential. |
| `src/samourai.ts` | Samourai's wire format, for stock-wallet compatibility. |
| `src/soroban.ts` | Soroban JSON-RPC client, `encodeDirectory`, Ed25519 confidential auth. |
| `src/register.ts` | Notification-less registration (customer + `Registrar`) and the customer registry. |
| `src/watcher.ts` | Turns the registry into the gap-limited address set to watch, with a pluggable used-address oracle. |
| `src/seed.ts` | BIP39 mnemonics: generate, import, and legacy hex seeds. |
| `src/state.ts` | Durable state, atomic writes, and the permanent network lock. |
| `src/server.ts` | The onion-facing storefront. Exposes the PayNym and nothing else. |
| `src/config.ts` | Paths and local service endpoints. |
| `src/discover.ts` | Finds the Dojo's indexer and Soroban, proven by protocol not open ports. |
| `src/torrc.ts` | Merges our hidden service into a shared torrc, reversibly. |
| `bin/paynym-bot.ts` | CLI: `init`, `start`, `serve`, `status`, `doctor`. |
| `install.sh`, `uninstall.sh` | Guided install and reversible removal. |
| `test/` | Vector gate, protocol, regressions, state, storefront. |

## Operating the receiver

- **Choose the network once.** `init` asks mainnet or testnet and records it. That choice
  fixes the BIP47 derivation path and therefore the PayNym itself, so it cannot be
  changed later without becoming a different receiver. Every command refuses loudly on a
  mismatch.
- **Back up the recovery phrase AND the state file.** Receive keys cannot be re-derived
  from the seed alone: a BIP47 address depends on *both* parties' payment codes, so
  without the registered customer codes in `state.json`, money already received cannot be
  found.
- **A BIP39 passphrase is for compatibility, not security.** On an always-online box it
  must be supplied to the running service, so it sits beside the phrase and protects
  nothing. It exists so an imported wallet derives the same PayNym it does in your wallet
  app. Pass `--passphrase` on every command, or you get a different PayNym.
- **Your own indexer only.** Point the used-address oracle at your Dojo's Fulcrum over
  loopback. The watch list is your counterparty graph — never hand it to a public
  explorer.
- **The bot is hot by construction.** BIP47 receiving is ECDH with the receiver's private
  key; there is no watch-only variant. It does not spend, which removes transaction
  construction and signing from the codebase entirely, but anyone who extracts the
  account key can derive the spend keys themselves. Keep the float small and sweep to
  cold storage.
- **The storefront exposes only the PayNym and the network.** Not the customer list, not
  the watch addresses, not even a customer count — that set is your counterparty graph
  and its size is your trading volume.

## Status

- Derivation: verified against the official vectors (0–9), both directions, on mainnet
  and testnet. ✅
- Registration: offline end-to-end, including forged-signature, wrong-merchant, and
  attacker-writes-to-inbox cases. ✅
- Storefront: serves the PayNym over loopback for Tor to publish, and nothing else. ✅
- Init and durable state, with a permanent network lock. ✅
- Used-address oracle over the Electrum protocol, against Fulcrum or any electrs. ✅
- Daemon: listen and scan on guarded timers, state persisted before an inbox entry is
  removed, restart reproduces the watch window exactly. ✅
- Wallet: 12-word BIP39 phrase, generated or imported, verified against the BIP39
  vectors. ✅
- Deployment: guided installer with dry-run, Dojo service detection, reversible torrc
  merge, hardened systemd unit, and a dry-run-by-default uninstaller. ✅
- **Not yet done:** an acceptance run on testnet against a real Dojo — open the onion,
  register from a wallet, send a payment, watch it credited with no notification
  transaction on chain. Everything above is exercised offline; that run is what proves
  it against a real chain.
- Samourai wire-format compatibility, verified against their compiled Java. ✅
- Also outstanding: a QR on the storefront, and sender-side index persistence.

## Requirements

Node 22+ (uses built-in TypeScript type stripping via
`--experimental-strip-types`; no build step). Dependencies are the audited
noble/scure family plus tweetnacl — see `package.json`.

## License

GNU General Public License v3.0 only. See [LICENSE](LICENSE).
