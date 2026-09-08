# heyl — Design

A third-party command-line client for heylogin, in Rust, built against the protobuf schema in
`descriptors/heylogin.binpb` and the protocol specification in `HEYLOGIN_SPEC.md`.

Decisions marked **⚠ PROPOSED** were not settled in the design interview; they are my
recommendation and are open for revision. Everything else is decided.

---

## 1. Purpose

Secret retrieval for shells and scripts. Fetch a password, TOTP code or custom field by name,
pipe it into other tools, inject it into a child process's environment.

```
$ heyl get github.com --field password
$ heyl totp aws-prod
$ heyl list --format json | jq -r '.[].title'
$ heyl run --env-file .env.tpl -- terraform apply
```

The reference points are `op read` and `pass show`, not a terminal UI for managing a vault.

## 2. Scope

### In

- **Read** every vault type that carries credentials.
- **One write**, and only one: the CLI's own `SessionMetadata` entry in the META vault, so the
  session appears as a named, revocable device in the heylogin app (§7).
- Login via **phone swipe (PUSH)** and **recovery code (BACKUP_CODE)**.
- Commands: `login`, `logout`, `list`, `get`, `totp`, `run`, `completion`, `session list|revoke`.

**Scheduled, after the core is done (see §7):** WebAuthn / FIDO2 login (M9), device-to-device
unlock (M10), Windows support (M11).

### Out (non-goals)

| Not doing | Why |
|---|---|
| Creating / editing / deleting logins | Requires heymerge commit generation for arbitrary content; a bug corrupts real vault data. |
| Organization admin surface | `ORGANIZATION_ADMIN`, `ORGANIZATION_LOGIN_SUMMARY`, `OrganizationService` (24 methods), the admin `ProfileProfileLock` chain. A different product. |
| Realtime sync (centrifugo) | Only Rust crate is `centrifuge-client` 0.1.0-alpha.2 (816 downloads). Polling `SyncService.Sync` is correct for a process that runs and exits. |
| Account creation (sign-up for a new heylogin account) | `CreateWithProfile` requires `VaultCreationData.first_commit_blob` — authoring a heymerge document from nothing, i.e. general write support. Users sign up in the web/mobile app; the CLI only logs into an existing account. |
| Browser integration, autotype, import/export, passkeys | Out of the product's shape. |

### Vault coverage

Ten vault types map to **five** content schemas; we implement three.

| Vault type | Schema | In v1 |
|---|---|---|
| `META` | `MetaVaultContentV2` | ✅ session registry — required by the write above |
| `PRIVATE` | `LoginVaultContentV2` | ✅ |
| `TEAM` | `LoginVaultContentV2` | ✅ |
| `ORGANIZATION_PERSONAL` | `LoginVaultContentV2` | ✅ |
| `INBOX` | `LoginVaultContentV2` | ✅ holds real logins in transit |
| `TEAM_META` / `INBOX_META` | `TeamMetaVaultContentV2` | ✅ team names + membership |
| `ORGANIZATION_ADMIN` | `OrganizationAdminVaultContent` | ❌ |
| `ORGANIZATION_LOGIN_SUMMARY` | `OrganizationLoginSummaryVaultContent` | ❌ |

Every credential in the system lives in `LoginVaultContentV2`, so team logins parse with the
same code as personal ones. Vaults are opened by `VaultProfileLock{locking_profile_id}`, and
every profile carries a `ProfileAuthenticatorLock` for every authenticator (§4) — so profiles
unlock **directly** from the authenticator. `ProfileProfileLock` is an admin-side mechanism.
Supporting team vaults is a loop, not a new mechanism.

---

## 3. Security design

### Unlock model

The seed is **never at rest**. The keychain holds exactly two items:

```
access_token       — bearer token for the backend
session_priv_key   — this session's X25519 private key
```

Nothing stored locally can decrypt vault content. Every invocation:

```
token ──► SyncService.Sync ──► SyncUpdate.session_unlock.encrypted_secret
                                      │
       asym_decrypt(session_priv_key, ·) ──► seed (32 bytes, in memory)
                                      │
              derive high-security + storable keys ──► vaultSecret / protectedSecret
                                      │
                          decrypt ──► emit ──► zeroize
```

The backend refuses to serve the unlock blob after `expiresAt`, so **§6's re-swipe control is
enforced server-side rather than cooperatively**. This is the central security property of the
design: a stolen laptop yields a token and a session key, neither of which decrypts anything
once the unlock window has closed.

Consequence, accepted deliberately: once the unlock expires, *every* command needs a swipe,
including `list`. There is no locked-but-browsable state, because storable keys are not
persisted either.

### Session registration

At `login`, while the seed is briefly held, the CLI:

1. self-grants an unlock — `SessionService.CreateSessionUnlock(session_id,
   asym_encrypt(own session encPubKey, seed), authenticator_id, max_expires_at)`;
2. writes its `SessionMetadata` entry into the META vault.

`SessionMetadata` = `{encPubKey, encPubKeySignature, signingAuthId, creationTime, editTime}`
plus optional `{description, iconType, isSelfUnlocking}`, wrapped with `{updateTime, isDeleted}`.
`encPubKeySignature` is produced with the high-security identity key (context
`salt-session-encryption-key-signature-`), so this write is only possible while unlocked — it
can never happen during an ordinary read.

`logout` writes a tombstone (`isDeleted: true`) and calls `DeleteSession`.
**No other command ever commits.** There is no periodic refresh: `SyncUpdate.Session` already
carries `last_used_at` server-side, so refreshing `updateTime` would tell the app nothing new.

### Writing safely

A commit blob is the **full serialized state**, not a delta, and `CreateCommitRequest` carries
`latest_commit_id`. So the write is read-modify-write under optimistic concurrency and **no
merge is ever executed**. Rails:

- operate on raw JSON, preserving unknown keys (the schemas use `objectPassthrough` deliberately);
- refuse to write if the content descriptor version is not `DESCRIPTOR_VERSION_HEYMERGE = 2`;
- guard with `latest_commit_id`; on rejection, re-read and retry once, then fail loudly;
- the entry key is unique to our session, so no other client ever writes it. heymerge is
  last-write-wins per key on `updateTime` — with a key we exclusively own, we cannot lose a merge.

### Memory hygiene

Seed and derived keys live in `Zeroizing<[u8; 32]>` / `secrecy::Secret`, never in `String`.
Secret values are written to the output sink and dropped; they are never logged, never included
in error messages, and never passed as command-line arguments to child processes.

### Threat model

| Threat | Mitigation |
|---|---|
| Laptop stolen, unlock expired | Keychain yields token + session key; neither decrypts anything. |
| Laptop stolen, unlock live | Attacker can read secrets until expiry — same exposure as an unlocked browser session. |
| Malicious process reading our memory | Not defended (no OS defends this meaningfully); minimised by short process lifetime. |
| Shoulder-surfing / shell history | `run` keeps secrets out of files and history; `get` prints only what was asked for. |
| Backend compromise | Backend holds only ciphertext; unchanged from heylogin's own design. |

---

## 4. Architecture

```
heyl/
├── descriptors/              heylogin.binpb — the sole committed schema artifact
├── tests/fixtures/protocol/  recorded gRPC-Web exchanges (M0)
├── tools/extract-protos.py   regeneration + round-trip verification
└── crates/
    ├── heyl-proto/       generated types + service clients
    ├── heyl-crypto/      §2 primitives, KDF, key hierarchy      [pure]
    ├── heyl-vault/       serialize format, heymerge parse, schemas  [pure]
    ├── heyl-ports/       trait definitions ONLY — no platform code, no adapters
    ├── heyl-client/      transport, auth, sync, unlock          [depends on ports]
    ├── heyl-platform/    adapters: linux / macos / windows / headless
    └── heyl-cli/         clap surface, output, wiring
```

Two boundaries carry the weight.

**Purity.** `heyl-crypto` and `heyl-vault` are I/O-free, so they are exhaustively
testable against fixtures with no network and no account. That is where the correctness risk
concentrates, and it is the main testability lever.

**Ports and adapters.** Nothing above `heyl-platform` may reference an OS API. Every
platform-specific capability is a trait in `heyl-ports`, implemented per platform in
`heyl-platform` and selected at compile time. `heyl-client` and `heyl-cli` are
written against the traits and are identical on every target.

| Port | Responsibility | Linux | macOS | Windows |
|---|---|---|---|---|
| `SecretStore` | store/fetch/delete `access_token`, `session_priv_key` | `keyring` (Secret Service / keyutils) | `keyring` (Keychain) | `keyring` (Credential Manager) |
| `Paths` | config / state / runtime directories | `directories` (XDG) | `directories` | `directories` |
| `Terminal` | TTY detection, hidden input, QR rendering, prompts | termios | termios | Console API |
| `FidoDevice` | CTAP2 `hmac-secret` transport (M9) | `ctap-hid-fido2` | `ctap-hid-fido2` | **`WebAuthn.dll`** — HID is not directly claimable |
| `ProcessRunner` | spawn child with injected environment for `run` | fork/exec | fork/exec | CreateProcess |

Two adapters exist on every platform regardless of OS:

- **`HeadlessSecretStore`** — reads `HEYL_TOKEN` / `HEYL_SESSION_KEY` from the
  environment. This is what makes CI work on a Linux box with no Secret Service, and it is a
  port implementation rather than a special case threaded through the code.
- **In-memory / fake adapters** — used by the test suite, so end-to-end tests run without
  touching a real keychain or terminal.

Consequence: adding Windows is implementing five traits, not editing the client. That is the
whole point of the boundary, and it is why M11 is sized S rather than a rewrite.

### Transport — decided at M0, empirically

**gRPC-Web is the only protocol the backend speaks.** Probed directly against
`https://heylogin.app/api/v1`:

| content-type | result |
|---|---|
| `application/grpc-web+proto` | **200, `grpc-status: 0`** |
| `application/grpc-web+json` | 200 |
| `application/proto`, `application/connect+proto` | **415** — Connect is not served |
| `application/grpc` | **505** — rejected at the edge |

So the previously proposed transport trait and `--transport connect|grpc-web` escape hatch are
both **dropped**: they hedged an unsettled choice, and a flag offering Connect would offer a
setting that always fails. HTTP/1.1 works, so there is no HTTP/2 requirement.

**Request metadata.** `client-type` is **mandatory and validated against the `ClientType`
enum** — omit it, or send `999` or `abc`, and every call returns `grpc-status: 13` with
`DomainError` 10400 `BAD_REQUEST`. `client-type: 400` (`CLIENT_TYPE_CLI`) is accepted, so no
impersonation of `CLIENT_TYPE_WEB` is needed. `client-version` is *not* validated on
unauthenticated methods (`0.0.0`, empty and `not-a-version` all pass; `CLIENT_OUTDATED` never
fired) — whether an authenticated method gates on it is still unknown and needs an account. A
custom `user-agent` and a `sync-version` header are both accepted.

We send our own crate version and identify ourselves honestly:
`client-type: 400`, `client-version: <crate version>`,
`user-agent: heyl/<version> (+<repo url>)`.

**Errors.** Responses are trailers-only, carrying `grpc-status`, `grpc-message` and
`grpc-status-details-bin` — base64 (standard alphabet, unpadded) of a `google.rpc.Status` whose
`details[0]` is an `Any` of `domain.DomainError {code, user_title, user_detail, request_id}`.
`domain.Status` in `errors.proto` is structurally identical to `google.rpc.Status`, so the
schema decodes its own error envelope with no extra dependency. The backend distinguishes
absent credentials (status 16, `DomainError` 30100) from rejected ones (status 7, 30420).
Four exchanges are recorded in `tests/fixtures/protocol/`.

**Codegen stack — measured, not assumed.** M0 built the whole surface twice, at full parity.
Both stacks consume `descriptors/heylogin.binpb` directly (`connectrpc_build::Config::
descriptor_set`, `tonic_prost_build::compile_fds`); **neither needs `protoc` or `buf`, and
neither ever reads a `.proto` file.** Both generated all 19 service clients and all 123 method
paths, both compiled with zero warnings, both round-tripped `Ping` and decoded
`DomainError{30100}`, and both encoded a nested `SyncUpdate` to the identical 120 bytes.

| | `connectrpc` 0.9 + `buffa` | `tonic` 0.14 + `prost` |
|---|---|---|
| codegen | 5,272 ms | **218 ms** |
| clean release build | 51.9 s | **39.0 s** |
| rebuild after schema change | 20.6 s | **6.0 s** |
| stripped binary | 6.80 MB | **3.99 MB** |
| generated code | 199,289 lines | **10,838 lines** |
| `grpc-status-details-bin` | decoded natively into `ErrorDetail` | raw bytes; ~10 lines to decode |
| maturity | pre-1.0 | widely deployed |

**Decision: `tonic` + `prost` + `tonic-web`'s `GrpcWebClientLayer`.** This reverses the earlier
proposal. `connectrpc`'s headline advantage — a first-party implementation that passes the
Connect conformance suite — is moot, because the backend does not serve Connect; we use only
gRPC-Web, which `tonic-web` speaks too. Its one real remaining advantage, native error-detail
decoding, is worth about ten lines. Against that, `tonic` generates 18× less code, regenerates
24× faster, and produces a 41% smaller binary, on a far more mature dependency.

Two things to get right, both found the hard way at M0:

- `tonic`'s generated code assumes the `transport` feature — which pulls in a *server* and
  `axum` — unless codegen is configured with `.build_transport(false)`.
- `rustls` sees both `ring` and `aws-lc-rs` through the dependency graph, so the process-level
  `CryptoProvider` must be installed explicitly or TLS panics on first use.

### Crypto crates — decided at M0

| Need (§2) | Crate |
|---|---|
| XSalsa20-Poly1305 secretbox, X25519 crypto_box | `dryoc` 1.0 (pure-Rust libsodium port, libsodium-shaped API) |
| Raw X25519 shared point (SAS) | `x25519-dalek` |
| Ed25519 | `ed25519-dalek` |
| SHA-512, HMAC-SHA256 | `sha2`, `hmac` |
| Argon2id (recovery code) | `argon2` |
| AES-GCM (newer material) | `aes-gcm` |
| Snappy (`0x01` framing) | `snap` |
| Zeroization | `zeroize`, `secrecy` |

`dryoc` is chosen over RustCrypto's `nacl-compat` because §2 is specified as
"libsodium-equivalent", so a libsodium-shaped API transcribes rather than reconstructs.

**Verified at M0.** All nine crates above compile together, and `cargo tree` over the whole
graph contains no `cc`, no `cmake` and no `*-sys` crate — the "pure Rust" claim holds as
stated. A `x86_64-unknown-linux-musl` build of that set links `static-pie` with no C toolchain
present.

**But the TLS layer breaks the claim, and it is worth being precise about where.** Both
`ring` and `aws-lc-sys` are C projects driven by `cc`/`cmake`, and rustls pulls one or the
other. A musl build of the *client* therefore fails with
`failed to find tool "x86_64-linux-musl-gcc"`. So "clean static cross-compilation" is true of
our crypto, and false of the binary as a whole: **M7's static musl artifacts need a musl C
cross-toolchain** (`cargo-zigbuild` or `cross`), not merely `rustup target add`. This is a
packaging requirement, not a code change — but it is the kind of thing that is much cheaper to
know now than during a release.

### FIDO2 / WebAuthn login (M9)

Per §4, `seed = deriveSecretFromSeed(prf, null, 'salt-authenticator-webauthn-seed-')`, where
`prf` is the key's PRF output for the authenticator's stored `prfSalt`. The assertion is
**never sent to the backend** — the FIDO device is purely a local key-derivation gadget, and the
backend only ever sees the ordinary seed-signed login challenge. That removes any need for
attestation, origin checks or a browser.

What it does need is CTAP2 `hmac-secret` over USB HID, via **`ctap-hid-fido2`** 3.6 (245K
downloads, actively released). Requirements:

- RP ID `heylogin.app`, credential id from the authenticator's stored `webauthnId`;
- `userVerification: required` → touch **and** PIN/fingerprint;
- heylogin reads `prfExtensionResult.first`, falling back to `.second` for a second WebAuthn
  authenticator sharing one credential (`getPrfSeed` in `client-core/src/util/webauthnUtil.ts`),
  so both evaluation points must be requested.

**The trap.** heylogin's clients call `navigator.credentials.get()` with `prf.eval.first =
prfSalt`, and the *browser* transforms that salt before handing it to CTAP:

```
actualSalt = SHA-256( UTF8("WebAuthn PRF") || 0x00 || prfSalt )
```

A native client speaking CTAP2 directly gets no such transformation for free. Omit it and the
key returns a perfectly valid HMAC output that derives a completely wrong seed — login fails
with no diagnostic pointing at the cause. M9 must replicate this and cross-check the derived
seed against one obtained through the web app.

### Device-to-device unlock (M10)

When the unlock window has closed, instead of a phone swipe the CLI can ask an
already-unlocked session — typically the browser extension — to grant it one. As the
*requesting* side the CLI does:

1. `SessionService.RequestSessionUnlock(source)` — registers a pending request, which heylogin
   broadcasts over centrifugo to connected sessions.
2. Poll `SyncService.Sync` until `SyncUpdate.session_unlock` appears, or time out.
3. Decrypt it with the session private key — the *same* path as §3. No new crypto.
4. On timeout or Ctrl-C, cancel with
   `DeleteSessionUnlock(session_id, only_pending_request: true)`.

**The CLI needs no centrifugo client.** The broadcast only has to reach the *granting* browser;
the requester learns the outcome by polling `Sync`, which the normal read path already calls.
That removes the alpha-quality `centrifuge-client` dependency from this feature entirely — the
reason it was previously deferred.

Prerequisite is **M5**: before encrypting the seed to us, the granting session runs
`checkEncPubKeySignature` against our published `encPubKey` (context
`salt-session-encryption-key-signature-`), so our `SessionMetadata` entry must already exist and
be correctly signed.

⚠ **Unknown.** `source` is a typed `UnlockRequestSource`; the only literal recoverable from the
bundles is `'ExtensionAutotype'` — the module itself is type-only and was elided from the source
maps. The accepted set, and whether the backend validates it at all, must be determined
empirically.

#### Dependency rules — decided: seven crates

A crate boundary is only a guarantee if the dependency graph is stated and enforced. The
allowed edges:

| Crate | May depend on | Must **not** depend on |
|---|---|---|
| `heyl-proto` | `tonic`, `tonic-web`, `prost`, `prost-types` | any other `heyl-*` |
| `heyl-crypto` | `dryoc`, `*-dalek`, `argon2`, `sha2`, `hmac`, `zeroize`, `secrecy` | any runtime, any transport, any other `heyl-*` |
| `heyl-vault` | `heyl-crypto`, `serde_json`, `snap`, `jiff`, `uuid` | any runtime, any transport, `heyl-proto` |
| `heyl-ports` | trait plumbing only (`async-trait`, `secrecy`) | every adapter and every other `heyl-*` |
| `heyl-client` | `heyl-proto`, `heyl-crypto`, `heyl-vault`, `heyl-ports`, `tokio`, `hyper`, `rustls` | **`heyl-platform`** |
| `heyl-platform` | `heyl-ports`, `keyring`, `directories`, `crossterm`, `rpassword`, `qr2term`, `ctap-hid-fido2` | `heyl-client` |
| `heyl-cli` | everything — this is the only crate that wires adapters into the client | — |

Two edges do the real work. **`heyl-crypto` and `heyl-vault` cannot reach the network**, because
they do not depend on a runtime or transport at all — not by convention, but because the symbols
do not exist. And **`heyl-client` cannot see `heyl-platform`**, so it is physically incapable of
calling an OS API; composition happens once, in `heyl-cli`. That is what makes the ports real
rather than decorative, and it is why the split is worth seven publishes on crates.io.

Enforce it in CI with a `cargo tree`-based check (or `cargo-deny` bans) so a violation fails the
build rather than relying on review to catch a new dependency line.

### Reused crates

Beyond the crypto and transport tables above. Download figures are a maturity signal, not an
endorsement; everything here gets pinned.

| Concern | Crate | Ver | Note |
|---|---|---|---|
| **Keychain** | `keyring` | 4.2 | macOS Keychain, Windows Credential Manager, Linux Secret Service **and** keyutils, in one API. 24M downloads. |
| **Platform paths** | `directories` | 6.0 | XDG / Known Folder / macOS Standard Directories. |
| **CLI** | `clap` + `clap_complete` | 4.x | Parser and generated shell completions (M6). |
| **Hidden input** | `rpassword` | 7.5 | Recovery code entry without echo; unix, windows, macOS. |
| **Terminal** | `crossterm` | 0.29 | TTY capabilities. `std::io::IsTerminal` covers plain detection. |
| **QR** | `qr2term` | 0.3 | Terminal QR (M4). Encoding via `qrcode` if we need control over quiet zone/polarity. |
| **TOTP** | `totp-rs` | 6.0 | RFC 6238 (M6). |
| **Timestamps** | `jiff` | 0.2 | ISO 8601 — see the ordering constraint below. |
| **JSON** | `serde_json` (`preserve_order`) | 1.x | `preserve_order` is **required**, not optional — see below. |
| **UUID** | `uuid` | 1.x | heymerge element keys. |
| **Errors** | `thiserror` / `anyhow` | 2.x / 1.x | Typed in libraries, contextual in the binary. |
| **Snapshot tests** | `insta` | 1.48 | Vault-decode and output-format fixtures. |
| **CLI tests** | `assert_cmd`, `predicates` | — | Exit codes and the stdout/stderr contract of §5. |
| **Property tests** | `proptest` | 1.x | heymerge round-trip fidelity. |
| **Packaging** | `cargo-dist` | 0.32 | Cross-platform binaries + installers for M7. |
| **TLS roots** | `rustls-platform-verifier` | 0.6 | OS trust store — matches what heylogin's browser-based clients do, and survives TLS-inspecting corporate proxies. |
| **Async runtime** | `tokio` | 1.x | `current_thread` flavour: measured ~650 µs cheaper per invocation than `multi_thread`, identical binary size. |

#### Two of these are load-bearing, not conveniences

**`serde_json` with `preserve_order`.** The vault content schemas use `objectPassthrough`, so
unknown keys must survive a read-modify-write untouched. Default `serde_json` maps are sorted;
`preserve_order` backs them with `IndexMap` and retains insertion order. Without it, our
`SessionMetadata` commit silently reorders every key in the META vault document. Pair it with a
`proptest` that asserts parse→serialize is byte-identical on real commit blobs.

**ISO 8601 formatting is semantic, not cosmetic.** heymerge resolves conflicts with
`leftUpdateTime > rightUpdateTime` — a *lexicographic string comparison*. Our timestamps must
therefore be byte-compatible with what JavaScript's `Date.toISOString()` emits:
`YYYY-MM-DDTHH:MM:SS.sssZ` — always UTC, always the literal `Z`, always exactly three fractional
digits. Emit `+00:00`, or nanosecond precision, and ordering against other clients' timestamps
breaks in ways that are invisible until a merge goes the wrong way. Pin the format explicitly
and test it against known JS output.

#### What this does to the ports

`keyring` and `directories` mean two of the five ports contain **no OS-specific code of our
own** — the adapter delegates. The ports stay, because they are what let us bind
`HeadlessSecretStore` for CI and fakes for tests, but they get thin.

The exception is `FidoDevice`. On Windows, non-elevated processes cannot claim FIDO HID devices
directly; access goes through the system `WebAuthn.dll` API instead. So M9 (FIDO2) and M11 (Windows)
intersect at exactly one place, and it is the one port where the Windows adapter is
real work rather than delegation. Sequence M9 before M11 and treat that as its known cost.

### Distribution channels

| Channel | Artifact | Compiles on user's machine? |
|---|---|---|
| GitHub Releases | static binary per target + curl installer (musl needs a C cross-toolchain — see §4) | no |
| npm | platform packages via `optionalDependencies`, wrapping the same binary | no |
| PyPI | platform-tagged wheels via `maturin`, wrapping the same binary | no |
| crates.io | source | **yes** |

One build feeds the first three; `cargo-dist` produces them. crates.io is the odd one out and
the only one that imposes constraints on the codebase:

- **`protoc` is not a build-time requirement, and generated code is not committed.**
  `tonic_prost_build::compile_fds` reads `descriptors/heylogin.binpb` directly, so `build.rs`
  needs nothing on `PATH`. M0 measured the cost of generating at build time: 218 ms of codegen
  inside a 39 s clean release build — noise. Committing 10,838 lines of generated Rust to save
  0.2 s would trade a large diff on every schema bump for nothing, so the descriptor set stays
  the only committed artifact.
- **Publishing `heyl` means publishing all seven workspace crates**, since `cargo publish`
  rejects path dependencies without versions. Automate with `release-plz`; mark the six library
  crates as internal with no API-stability guarantee in their READMEs.

The seven-crate split is kept regardless — see the dependency rules above. Collapsing to one
crate with modules would reduce compiler-checked guarantees to convention, which is a worse
trade than seven publishes.

crates.io publication happens at **M8**, not before — the name is reserved earlier with a
placeholder so it cannot be taken in the meantime.

### Vault decode path

```
ListCommits ─► blob ─► symDecrypt(vaultSecret, ·) ─► first byte selects format:
                                                       0x01 → Snappy (raw block)
                                                       0x5B → JSON  (automerge, legacy)
                                                       0x7B → JSON  (heymerge)
                                                     ─► {type, version, content}
                                                     ─► content.<list> : map<id, element>
```

Elements are `{...fields, updateTime, isDeleted}`. Filter tombstones (`isDeleted: true`) and
archived entries (`isArchived: true`) from `list` output. Protected values decrypt as
`symDecrypt(protectedSecret, encrypted)`.

Legacy `0x5B` automerge documents are **read-only and best-effort**: if we encounter one we
report it rather than guess.

---

## 5. Command surface

### Selector semantics — ⚠ PROPOSED

`get`, `totp` and friends take a selector resolved in this precedence order:

1. exact login id (uuid)
2. exact `title` match, case-insensitive
3. exact website host match
4. unique case-insensitive substring of `title`

Scoped by `--vault <name|id>` when given. **Ambiguity is an error, never a guess**: exit code 3,
candidates listed on stderr, nothing on stdout. Determinism matters more than convenience in a
tool that runs unattended.

### Output contract — ⚠ PROPOSED

- A secret goes to **stdout, raw**, with a trailing newline only when stdout is a TTY, so
  `$(heyl get x)` is exact and interactive use still looks right.
- Everything else — prompts, progress, QR codes, warnings — goes to **stderr**.
- `--format json` on `list` and `get` emits a stable, documented shape. `--format` is the only
  compatibility promise; human table output may change.
- Secrets never appear in logs, errors, or `--format json` unless explicitly requested.

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | generic failure |
| 2 | not found |
| 3 | ambiguous selector |
| 4 | unlock required / expired |
| 5 | network or backend error |

### `run`

`heyl run --env-file .env.tpl -- <cmd>` resolves `heyl://<vault>/<item>/<field>`
references in the template into the child's environment. Secrets are passed via the environment
of the spawned process only — never written to disk, never in argv, never in shell history.

### QR rendering (M4)

QR is needed by exactly one flow — phone-swipe login. Recovery code (M2), FIDO2 (M9) and
device-to-device unlock (M10) all need none. And once M10 lands, QR is a **once-per-machine
onboarding step**, not a daily interaction, which caps how much polish it warrants.

The payload is not inherently graphical: per §5 of the protocol spec it is the URL
`https://heylogin.app/qr/#<base64url(pubKey)>`, about 68 characters. The QR is merely a
transport for that string, so the string is always available as a fallback.

At 68 characters the code is ~33–37 modules; rendered with Unicode half-blocks (`▀`/`▄`) that is
roughly **37 columns × 19 rows**, which fits an 80×24 terminal.

Behaviour, implemented behind the `Terminal` port:

- Render the QR when stdout is a TTY.
- **Always print the URL underneath, on stderr**, whether or not the QR rendered. One line, and
  it is the difference between a recoverable and an unrecoverable login attempt.
- `--qr <utf8|ascii|none>`. ASCII (two spaces per module) is twice as wide but survives fonts
  with non-square cells or ligatures.
- Never render when output is piped or under `--format json` — URL only.

Two failure modes to get right, because both fail *silently* — the code renders, looks correct,
and simply will not scan:

- **Quiet zone.** Emit the full 4-module margin. A flush-to-edge QR is unreadable by most phones.
- **Polarity.** Dark-background terminals need the modules inverted. Detect or expose it; do not
  assume light-on-dark.

`qrcode` or `qr2term` handle encoding; the rendering choice belongs in the port adapter, since
it depends on terminal capabilities.

### Headless operation

`login --recovery-code` reads from `HEYL_RECOVERY_CODE` or stdin, never argv. On a headless box with no
Secret Service, the `SecretStore` port is bound to `HeadlessSecretStore`, which reads
`HEYL_TOKEN` / `HEYL_SESSION_KEY` from the environment — an adapter swap, not a special
case threaded through the code.

The CLI warns loudly that a recovery code in CI is a standing master credential (§4: reusable,
not one-time, and it unlocks every vault).

---

## 6. Testing

| Layer | Approach | Needs an account? |
|---|---|---|
| Primitives (§2) | Known-answer tests from libsodium/tweetnacl vectors | No |
| KDF & key hierarchy (§3) | Fixed-seed vectors; assert every context salt derives a stable key | No |
| Vault decode | Recorded commit blobs + their expected plaintext, checked in redacted | No |
| heymerge round-trip | Property test: parse → serialize preserves unknown keys byte-for-byte | No |
| Protocol | Recorded request/response fixtures replayed against the transport trait | No |
| Port adapters | Fake `SecretStore` / `Terminal` / `ProcessRunner`; the suite never touches a real keychain | No |
| End-to-end | Throwaway account with a `DUMMY` authenticator, hidden `--dummy` login path | Yes |

The `DUMMY` authenticator (`secretInfo = JSON.stringify({seed})`) makes fully automated e2e
tests possible with no phone in the loop. It is **test-only, behind a hidden flag, never a
user-facing auth method**. The test account is created manually in the web app and paired once —
programmatic account creation is out of scope.

Note that the crypto and vault layers need no account at all, which is where the correctness
risk actually concentrates.

---

## 7. Milestones

Sizing is relative effort, not calendar commitment; assume one engineer part-time.
Milestones are work units, not releases — a version number gets assigned when something is
actually released.

| # | Milestone | Exit criterion | Size |
|---|---|---|---|
| **M0** | ✅ **Codegen viability spike** — both stacks built at full parity from `descriptors/`, protocol settled empirically | Done: gRPC-Web confirmed sole protocol; `CLIENT_TYPE_CLI` accepted; 19/19 services and 123/123 methods generated by both stacks with zero warnings; `Ping` and `DomainError{30100}` verified live; `tonic` chosen on measured criteria | M |
| **M1** | **Crypto core** — §2 primitives, `deriveSecretFromSeed`, all context salts, key hierarchy | KAT suite green; fixed seed → stable keys | M |
| **M2** | **Recovery-code login** — `CreateChallenge`→`CreateTokens`, Argon2id seed, `SecretStore` port | `heyl login --recovery-code` yields a usable token | M |
| **M3** | **Read path** — `Sync`, `ListCommits`, profile/vault unlock, serialize + heymerge parse | `heyl list` and `get --field password` work against a real account | **L** |
| **M4** | **Phone swipe** — long-poll channel, QR in terminal, session self-unlock | `heyl login` with a phone; unlock survives to next day 02:00 | M |
| **M5** | **Session registration** — `SessionMetadata` write, `logout` tombstone, `session list\|revoke` | CLI appears as a named device in the app and is revocable there | M |
| **M6** | **UX completion** — `totp`, `run`, `completion`, output contract, exit codes, error taxonomy | Full command set; `--format json` stable | M |
| **M7** | **Distribution** — `cargo-dist` binaries (linux/macOS × x86_64/aarch64), npm optionalDependencies, PyPI wheels | `npx`, `uvx` and curl-installer all run the same artifact | M |
| **M8** | **Hardening** — zeroization audit, fuzz the vault decoder, threat-model review, docs, **crates.io publish** | Ready to use daily | M |
| **M9** | **FIDO2 login** — CTAP2 `hmac-secret` via `ctap-hid-fido2`, WebAuthn-PRF salt transform, PIN/UV | A FIDO2 key derives the *same* seed as the web app and logs in | M |
| **M10** | **Device-to-device unlock** — `RequestSessionUnlock` + Sync polling + cancel-on-abort | An unlocked browser session can unlock the CLI; no phone needed | S |
| **M11** | **Windows support** — implement the five ports for Windows; no changes above `heyl-platform` | Same test suite green on Windows CI | S |

**Critical path: ~~M0~~ → M1 → M2 → M3.** M0 is done. M3 is the milestone that proves the whole
reverse engineering is correct; everything after it is addition rather than risk. M4 and M5 can proceed
in parallel with M6 once M3 lands.

The first genuinely useful build is **M3** — read-only, recovery-code login, no phone flow.
Worth dogfooding rather than waiting for M8.

M9 through M11 are independent of one another and can land in any order; none of them touches
the core, which is the intent behind the port boundary.

---

## 8. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| ~~Backend rejects an unofficial client~~ | **Closed** | Probed at M0: `client-type: 400` is accepted and `client-version` is not validated. Not a risk. |
| `tonic` / `tonic-web` API churn | Low | `tonic` is mature and widely deployed. `connectrpc` was built at full parity during M0 and works, so a switch back is a known quantity rather than a hope. |
| Static musl artifacts need a C cross-toolchain | Medium | Found at M0: `ring`/`aws-lc-sys` are C. M7 uses `cargo-zigbuild` or `cross`; not a code change, but it must be in the release pipeline from the start. |
| gRPC-Web streaming (`StreamingSync`, `LongPollSync`) from a native client is untested | Medium | **M0 did not retire this.** It is M4's exposure; retire it early in M4 rather than at the end. |
| A context salt or KDF detail is subtly wrong | Medium | Fails loudly (decryption fails), not silently. M1's KAT suite is the guard. |
| heymerge entry shape wrong → app misreads the device | Low | Single entry, exclusively-owned key, validated against the app's rendering at M5. |
| WebAuthn PRF salt transform missed → silently wrong seed | High if unguarded | Replicate `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ salt)`; cross-check against a browser-derived seed at M9. |
| Legacy automerge (`0x5B`) vaults in the wild | Low | Detected and reported, not guessed at. |
| Protocol changes under us | Ongoing | `tools/extract-protos.py` regenerates and re-verifies in one command. |

## 9. Naming, license, visibility

### Name — decided: `heyl`

One name everywhere: binary, crate, npm package, PyPI package. Free on all three registries as
of this writing; **reserve it with a placeholder publish** before M7, since they are first-come.

No `-cli` suffix. That suffix exists to disambiguate a tool from a library of the same name; no
`heyl` library is planned, so it disambiguates nothing and costs four characters on a command
typed dozens of times a day. `npx heyl get github.com` reads better than the alternative.

Rejected, with reasons worth keeping:

| Candidate | Why not |
|---|---|
| `hey-cli` | Taken on npm (a webpack scaffold, v2.7.1) **and** crates.io. `npx hey-cli` would run someone else's tool. |
| `hey` | Taken on all three. Also collides with rakyll/hey (HTTP load tester) and the HEY.com trademark. |
| `hl-cli`, `hl` | Taken; `hl` reads as "highlight" across all three registries. |
| `heylogin`, `heylogin-cli` | Free, maximally clear, but uses the mark *as* the identifier — the greyest ground. Fine for a private repo, avoidable for a public one. |
| `hlgn` | Free and neutral, but opaque and unpleasant to type. |

`heyl` is evocative of heylogin without being the mark, and short enough to stand as a tool name
rather than as a reference to someone else's product. Note "Heyl" is also a German surname and
an unrelated US engineering firm — different sector, package namespace, low concern.

### License — decided: Apache-2.0

Deliberately *not* the Rust-conventional dual MIT/Apache-2.0. Three clauses earn their place:

- **§3** patent grant and retaliation — worth having when implementing someone else's protocol.
- **§6** explicitly grants no trademark rights, so the license itself documents that we make no
  claim to the heylogin mark.
- **§4(d)** NOTICE file — a canonical home for the disclaimer below, which propagates to forks.

Dual-licensing would let a downstream user select MIT and drop the patent-retaliation term, and
here those terms are the point. GPL/AGPL buys nothing: this is a client binary, not a service,
and there is no proprietary-fork threat to guard against.

Shipped: `LICENSE` (Apache-2.0), `NOTICE` (disclaimer), and the same disclaimer as a callout at
the top of `README.md`.

The license governs our code and nothing else. It grants no rights to heylogin's protocol,
service or marks, and it does not shield the project from a terms-of-service or trademark
complaint. What lowers that risk is the disclaimer, not using the mark as the identifier, and
the interoperability purpose being evident. (Engineering judgement, not legal advice.)

### Visibility — decided: public

Consequences, all already provided for above:

- The NOTICE disclaimer and the README's first line are now load-bearing, not formalities.
- The name carries no trademark, which is the posture a public repo wants.
- `cargo install heyl` becomes an expectation, which is why crates.io is in the channel table
  and why generated protobuf code is committed.
- Issue templates should make the unofficial status explicit, so users do not report heylogin
  service problems here or expect vendor support.

Everything marked **⚠ PROPOSED** in this document is mine to defend but yours to overrule.
