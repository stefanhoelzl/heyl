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
- Login via **phone swipe (PUSH)**.
- **One recovery command**, `heyl recovery` — not a login. See below.
- Commands: `login`, `logout`, `list`, `get`, `totp`, `run`, `completion`, `session list|revoke`.

**Scheduled, after the core is done (see §7):** WebAuthn / FIDO2 login (M9), device-to-device
unlock (M10), Windows support (M11).

#### `heyl recovery` is a recovery, not a login

Earlier drafts listed a recovery-code login beside the phone swipe. It cannot be a *login*, for two
reasons established against the live backend and corroborated by heylogin's own Security Whitepaper
§6.5.4 — but it is worth having as an explicit, confirmed **recovery** command:

1. **It is destructive.** Using a `BACKUP_CODE` authenticator makes the server *delete the push
   authenticator and all its locks*, and restricts the resulting session to replacing the primary
   authenticator. Recovering from that means re-pairing the phone, which regenerates every profile
   and every `VaultProfileLock`. A password manager whose sign-in disconnects your phone is not a
   password manager. We observed exactly this on the test account.
2. **It is refused to a client that identifies as itself.** `CreateTokens` from a `BACKUP_CODE`
   authenticator returns `DomainError 30460` for `CLIENT_TYPE_CLI`, `WEB` and `EXT`, and is
   accepted only for the mobile client types.

So the command exists, and it is named for what it does. `heyl recovery`:

- **shows what it will disconnect** — `CreateChallenge` lists the account's authenticators before
  anything is committed, by type and id (there is no name: authenticators carry no description
  anywhere in the schema, and the friendly device names in heylogin's app are `SessionMetadata`
  *session* names, held in an encrypted vault we cannot read until afterwards);
- **asks, unless there is nothing to lose** — a second recovery, with the phone already gone, has
  nothing left to destroy and must not train anyone to dismiss a warning;
- **refuses when there is no terminal to ask at and no `--confirm`** — a destructive operation does
  not proceed silently because nobody was there to object;
- **says what was lost afterwards**, and that pairing a phone again regenerates every profile.

The consequence for daily use is unchanged: **`heyl` has no unattended login.** A session's unlock
expires the next day at 02:00 (and the server deletes the blob after 30 hours), so a headless box
needs a human swipe roughly daily. `HeadlessSecretStore` covers headless *operation* between those
points, not headless *login*. M10's device-to-device unlock is the path that would fix this without a
phone in the loop each time. Recovery is not that path — each use costs a phone pairing.

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

**That is our choice, not a limit of the protocol.** heylogin's Security Whitepaper §6.4.3 is
explicit that an unlocked session may persist the *storable* key pairs — `profileSeedEnc_s`,
`vaultKeyEnc_s`, `sig_s` — which lets a locked client still decrypt `vaultKeyₛ` and read titles,
usernames and websites (this is what the extension's on-page overlay uses). We decline, because
persisting them puts long-lived key material on disk for a tool whose whole pitch is that the
keychain holds nothing that decrypts anything. The cost is a swipe for `list`.

### Session registration

At `session create`, while the seed is briefly held, the CLI:

1. writes its `SessionMetadata` entry into the META vault;
2. self-grants an unlock **only if `--unlock` was asked for** —
   `CreateTokens(session_unlock: …)`. A session is otherwise born locked:
   pairing establishes an identity, approving an unlock is a separate act.

**Registration is not optional polish — it is the gate on everything.** Confirmed live: a
session with no `SessionMetadata` entry is invisible in the heylogin app, and
`RequestSessionUnlock` for it delivers a push that opens onto nothing when tapped. The phone
verifies `encPubKeySignature` against its trusted authenticator keys before it will unlock
anyone, so an unregistered session has nothing for it to verify and nothing to encrypt the seed
to. heylogin knows this failure: `RequestSessionUnlockRequest.source` exists, per its own
schema comment, to chase exactly these "ghost notifications".

heyl cannot detect the state it produces, either: the entry is vault content, so reading it
needs the unlock being asked for, and no `Sync` field reveals it. A device removed from the
phone is therefore indistinguishable from an approval nobody has given yet, and `unlock` says
so after waiting rather than pretending to know.

`SessionMetadata` = `{encPubKey, encPubKeySignature, signingAuthId, creationTime, editTime}`
plus optional `{description, iconType, isSelfUnlocking}`, wrapped with `{updateTime, isDeleted}`.
`encPubKeySignature` is produced with the high-security identity key (context
`salt-session-encryption-key-signature-`), so this write is only possible while unlocked — it
can never happen during an ordinary read.

`session remove` writes a tombstone (`isDeleted: true`) and calls `DeleteSession`; `session set
display-name` rewrites one field of the same entry. **No other command ever commits.** There is no periodic refresh: `SyncUpdate.Session` already
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

Secret material lives in newtypes that wrap `Zeroizing` bytes **and are `mlock`ed for the life of
the process**, so a seed or a `protectedSecret` is never written to swap. Those newtypes implement no `Deref`, no
`AsRef<[u8]>`, no `Serialize`, and a hand-written `Debug` that redacts — the bytes are reachable
only through an explicit `expose_secret()`, which makes every access site greppable in one query.

Core-dump exclusion is a *process* concern rather than a buffer concern, so `heyl-cli` sets
`RLIMIT_CORE = 0` at startup instead of pushing `madvise` into the leaf crypto crate. The two are
**not** redundant: `mlock` does not keep a page out of a core file, and `panic = "abort"` turns
every panic into a SIGABRT, so a crash holding a live seed would write it to the system's coredump
directory — the seed at rest, which this section says never happens.

**A failed `mlock` is fatal.** If the lock did not take, the "never reaches swap" claim above is
false, and continuing would ship a weaker guarantee than the README advertises; a warning on
stderr is not read by anyone in a tool built for scripts. `heyl` refuses to start instead, naming
`RLIMIT_MEMLOCK`. The failure is rare enough for that to be reasonable — locking is page-granular,
a handful of secrets is a handful of pages, and systemd has defaulted the limit to 8 MiB for
years.

**The lock is taken and never released, and that is what makes the claim true.** `mlock` is
page-granular: a 32-byte key shares its page with other secrets, so releasing a lock when one
secret drops unlocked the page under every other secret still live on it. That defect shipped from
M1 until the cross-platform CI matrix ran the suite on Windows, where `VirtualUnlock` keeps no lock
count and fails loudly the second time; on Linux and macOS it had been silent, and a test using
`/proc/self/smaps` now confirms the page really was left unlocked. The guard is therefore leaked
deliberately. Locking for longer than strictly necessary is the safe direction for a property that
means "never swapped while live", and the cost is bounded by measurement rather than hope: 5000
secrets created and dropped in sequence touch **one** page, and dozens held at once touch **three**
— against ~2048 pages of an 8 MiB `RLIMIT_MEMLOCK`, and Windows' ceiling of its minimum working
set (~50 pages) less overhead.

Secret values are written to the output sink and dropped; they are never logged, never included
in error messages, and never passed as command-line arguments to child processes.

### Threat model

| Threat | Mitigation |
|---|---|
| Laptop stolen, unlock expired | Keychain yields token + session key; neither decrypts anything. |
| Laptop stolen, unlock live | Attacker can read secrets until expiry — same exposure as an unlocked browser session. |
| Seed or `protectedSecret` reaches disk via swap or a core dump | **Mitigated**, not accepted: secret buffers are `mlock`ed, and `heyl-cli` sets `RLIMIT_CORE = 0`. A swapped page is a copy of the seed at rest, which §3 says never happens. |
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
    ├── heyl-crypto/      §2 primitives, KDF, typed contexts       [leaf, deterministic]
    ├── heyl-domain/      ids, enums, locks, Timestamp, unlock chain, domain rules  [pure]
    ├── heyl-vault/       serialize format, heymerge parse, schemas [pure codec]
    ├── heyl-ports/       trait definitions ONLY — no adapters, no platform code
    ├── heyl-app/         use cases — no tonic, no proto, no OS    [the core]
    ├── heyl-proto/       generated types + service clients
    ├── heyl-grpc/        HeylApi adapter; the ONLY crate that sees heyl-proto
    ├── heyl-platform/    adapters: linux / macos / windows / headless
    └── heyl-cli/         clap surface, output, wiring — the composition root
```

```
heyl-crypto                     deterministic primitives + KDF + typed contexts
     ↑
heyl-domain                     locks, ids, content types, Timestamp,
     ↑                          unlock chain, unprotect, domain rules
     ├── heyl-vault             serialize / heymerge / schemas
     ├── heyl-ports             SecretStore, Paths, Terminal, ProcessRunner,
     │                          FidoDevice, HeylApi, RandomSource, Clock
     └── heyl-app               use cases
              ↑
     heyl-grpc · heyl-platform · fakes
              ↑
          heyl-cli
```

Three boundaries carry the weight.

**Purity.** `heyl-crypto`, `heyl-domain` and `heyl-vault` are I/O-free, so they are exhaustively
testable against fixtures with no network and no account. That is where the correctness risk
concentrates, and it is the main testability lever. `heyl-crypto` goes further and is
**strictly deterministic**: every function is a total function of its arguments, and randomness
arrives as explicit bytes drawn from the `RandomSource` port by `heyl-app`. That is what makes
the *wire format* of `symEncrypt` / `asymEncrypt` fixture-testable at all — a fresh internal
nonce would make the output unpinnable.

**Ports and adapters — including the backend.** Nothing above the adapters may reference an OS
API *or the wire protocol*. `HeylApi` is a driven port like any other, so `heyl-app` cannot tell
gRPC from a fake, and the recorded exchanges in `tests/fixtures/protocol/` are replayed against a
fake implementation of it. `heyl-app` depends on the port traits, not on `tokio`; the runtime
lives in `heyl-cli`.

**Below that port, two layers rather than one** — added at M3, because the client had a
use-case-shaped view of heylogin and no statement of what heylogin's API *is*:

```
heyl-app ──uses──► heyl_ports::HeylApi      domain types, use-case shaped, ~12 methods
                        ▲
                   DomainApi<A>             the mapping, and the policy a raw layer must not have
                        ▲
                   HeyloginApi              prost types, 123 methods, generated
                        ▲
                   GrpcClient               transport, stateless
```

`HeyloginApi` is generated from `descriptors/heylogin.binpb` by `heyl-grpc/build.rs`: one method
per RPC, each defaulting to an error naming its own path, so a stub implements the two it
exercises and inherits 121. **Nothing is implicit at that layer** — `client-type`, `client-id`,
`client-version`, `user-agent` and the bearer token are all fields on a `Request<T>`, not state
hidden in the client. That is what makes it worth recording and replaying, and it is why
`CLIENT_TYPE_RECOVERY` is now a value at its one call site rather than a private method on the
transport.

`DomainApi<A: HeyloginApi>` holds what a raw layer must not: the wire→domain mapping, the token
(the port is deliberately stateful about it, since `RefreshToken` rotates it mid-run), and the
retry on an idempotent read. Being generic is the point — the port `heyl-app` depends on can be
driven by something that is not a socket.

**Composition happens once.** `heyl-cli` is the only crate that names an adapter. `heyl-app`
physically cannot reach `heyl-platform` or `heyl-proto`, because it does not depend on them.

| Port | Responsibility | Linux | macOS | Windows |
|---|---|---|---|---|
| `SecretStore` | store/fetch/delete `access_token`, `session_priv_key` | `keyring` (Secret Service) | `keyring` (Keychain) | `keyring` (Credential Manager) |
| `Paths` | config / state / runtime directories | `directories` (XDG) | `directories` | `directories` |
| `Terminal` | TTY detection, hidden input, QR rendering, prompts | termios | termios | Console API |
| `FidoDevice` | CTAP2 `hmac-secret` transport (M9) | `ctap-hid-fido2` | `ctap-hid-fido2` | **`WebAuthn.dll`** — HID is not directly claimable |
| `ProcessRunner` | spawn child with injected environment for `run` | fork/exec | fork/exec | CreateProcess |
| `HeylApi` | the backend, as ~12 use-case-shaped methods over domain types | `heyl-grpc` (tonic + `heyl-proto`) — identical on every platform |||
| `RandomSource` | all randomness: session keys, nonces, the long-poll keypair | `OsRng` |||
| `Clock` | the current instant, for unlock expiry and `updateTime` | system clock |||

Two adapters exist on every platform regardless of OS:

- **`HeadlessSecretStore`** — reads `HEYL_TOKEN` / `HEYL_SESSION_KEY` from the
  environment. This is what makes CI work on a Linux box with no Secret Service, and it is a
  port implementation rather than a special case threaded through the code.
- **In-memory / fake adapters** — used by the test suite, so end-to-end tests run without
  touching a real keychain or terminal.

The last three are platform-independent: they are ports because they isolate what the core cannot
control — the network, randomness and time — not because they differ per OS. `RandomSource` and
`Clock` exist so that every key-generation and every timestamp is deterministic under test;
`Clock` in particular guards §4's byte-exact `updateTime` format, where a merge silently resolves
the wrong way if the instant or the formatting is off.

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
`user-agent: heyl/<version> (+<repo url>)`, and a fresh `client-id` per invocation as the real
clients do.

**One recorded exception: `heyl recovery`'s `CreateTokens` sends `client-type: 200`.** heylogin
refuses to mint a session from a `BACKUP_CODE` authenticator for any browser-family client type
(`DomainError 30460`, for every session type including the proto3 zero) and accepts it from the
mobile ones. The commitment above was written against *routine* traffic — the objection to
impersonation is that a client would misstate itself on every request, forever. This is one call,
on a command the user has explicitly confirmed, which exists because their phone is gone. It is
scoped in `heyl-grpc` by session type, so `heyl-app` never learns that a client type exists, and
every other request this client makes says `400`.

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

**`tonic-web` is vendored and patched.** Upstream 0.14.6 drops gRPC-Web trailers when they arrive in
the same buffer as the final data frame, so any response over roughly 4 KiB fails with
`missing grpc-status trailer` on a response that in fact arrived intact — confirmed by fetching the
same request with `curl` and seeing a complete body. One line in `vendor/tonic-web`; see its README.
**A `[patch.crates-io]` reaches our builds and not anyone installing from crates.io**, so before M8
either upstream releases the fix or `heyl-grpc` stops relying on that decode path.

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

| Need (§2) | Crate | Ver |
|---|---|---|
| XSalsa20-Poly1305 secretbox | `crypto_secretbox` | 0.1 |
| X25519 crypto_box (NaCl `box` layout) | `crypto_box` | 0.9 |
| Ed25519 | `ed25519-dalek` | 3.0 |
| Raw X25519 shared point (SAS, M4) | `x25519-dalek` | 3.0 |
| SHA-512, HMAC-SHA256 | `sha2`, `hmac` | 0.11 / 0.13 |
| Argon2id (recovery code) | `argon2` | 0.6 |
| AES-GCM (newer material) | `aes-gcm` | 0.11 |
| Snappy (`0x01` framing) | `snap` | 1.x |
| Zeroization | `zeroize` | 1.x |
| `mlock` for secret buffers | `region` | 4.0 |

**RustCrypto is chosen over `dryoc`, on future-proofing.** `dryoc` is not an alternative to these
crates — it is a facade *over* them (it depends on `curve25519-dalek`, `salsa20`, `sha2`,
`subtle`). Depending on the base of the stack rather than a wrapper over it means there is nothing
to migrate off if the wrapper is abandoned, and the wrapper is the one with bus factor 1: one
author wrote 416 of `dryoc`'s 429 lifetime commits, and 58 of 58 in the last year. RustCrypto's
NaCl-compat line is quieter (9 commits, 2 authors) but sits inside an organisation, and it is
mid-migration rather than dormant — `crypto_box` 0.10-pre already targets `curve25519-dalek` 5.0
and the new trait generation.

Measured, 2026-09-09: the RustCrypto graph is 77 crates against `dryoc`'s 49, and carries two
copies of `curve25519-dalek` (4.1.3 via `crypto_box`, 5.0.0 via `ed25519-dalek`) — bloat, not a
correctness problem, since no curve type ever crosses between NaCl box and Ed25519. It resolves
when `crypto_box` 0.10 lands. Both graphs are free of `cc`, `cmake` and `*-sys`.

The cost of not using `dryoc` is that §2's libsodium vocabulary no longer maps one-to-one onto
call sites. `heyl-crypto` absorbs that by carrying a bundle-symbol → Rust-item table on its front
page, so the spec, the bundle and the code stay cross-referenceable.

**`secrets` was evaluated for `mlock` and rejected.** Its `build.rs` links the system libsodium
*unconditionally* — the `use-libsodium-sys` feature changes only how the library is found, not
whether it is linked — so it would require libsodium on every build machine and break the static
musl story. `region` 4.0 replaces it: `region::lock()` is a **safe** `fn` returning an RAII
`LockGuard`, so `heyl-crypto` gets `mlock` while keeping `unsafe_code = "forbid"`, and its
dependencies (`libc`, `mach2`, `windows-sys`, `bitflags`) are FFI declarations with no C library
behind them.

**What did not transfer with that swap, and cost us a defect.** `secrets` wraps libsodium's
`sodium_malloc`, which *allocates* each secret its own guarded pages — page ownership comes free
and unlocking is exact. `region` only *locks* pages someone else allocated; owning them is the
caller's job, and `region::unlock`'s own documentation says so ("unlocking one mapping may unlock
another mapping that shares the same page"). `SecretBytes` locked 32-byte heap allocations and
released them on drop, which unlocked pages under live secrets. The rejection of `secrets` was
right and is more right now — its `build.rs` would fail §6's `libsodium-sys` ban outright — but the
half it did for free had to be replaced rather than assumed. §3 records the fix: never unlock. What `region` does not give is `MADV_DONTDUMP`; core-dump suppression is a process
concern and lives in `heyl-cli` as `RLIMIT_CORE = 0`.

**Verified at M0, re-verified at M1 for the chosen stack.** The crates above compile together, and
`cargo tree` over the whole graph contains no `cc`, no `cmake` and no `*-sys` crate — the "pure
Rust" claim holds as stated. `libc` is present and permitted: it is an FFI *declaration* crate
with no C source and no build script needing a compiler. This is now enforced rather than
observed — see the `cargo-deny` ban in §6.

**The TLS layer used to break the claim; at M2 it stopped.** rustls has no cryptography of its
own — it takes a `CryptoProvider` — and both of the usual ones are C projects driven by
`cc`/`cmake`. M0 measured that, accepted `ring`, and recorded the consequence: a musl build of
the *client* fails with `failed to find tool "x86_64-linux-musl-gcc"`, so M7's static artifacts
would need a musl C cross-toolchain (`cargo-zigbuild` or `cross`) rather than merely
`rustup target add`.

M2 removed the exception instead of documenting it, because it was the first milestone whose
graph actually contained TLS and therefore the first time CI could see the contradiction — the
`cargo-deny` ban in §6 states the rule unconditionally, and `ring` failed it. The provider is
now **`rustls-graviola`**: pure Rust plus assembly from the [s2n-bignum] project that is
formally proven to implement the operation it claims, written by rustls' own author, and
depending on nothing but `cfg-if` and `getrandom`. `cargo tree` over the whole graph contains
no `cc` and no `cmake`, on every target we ship. So "clean static cross-compilation" is now true
of the binary as a whole, and the ban needs no wrapper exception.

**What that costs, stated plainly.** graviola is young — its own README says "this project is
very new, so exercise due caution" — and it is `x86_64` and `aarch64` only, with CPU-feature
floors: `aes/ssse3/avx/avx2/adx/bmi2/pclmulqdq` on x86_64 (roughly 2014 and later) and
`aes/sha2/pmull/neon` on aarch64, **which excludes Raspberry Pi 4 and earlier**. That is a real
narrowing for a tool §2 expects to run on headless boxes, and it is the reason the choice is
recorded here rather than left in a manifest. It is also contained: this provider secures the
transport to heylogin and nothing else. Every secret heyl handles is protected by heylogin's own
end-to-end crypto in `heyl-crypto` (RustCrypto), which no TLS provider touches.

[s2n-bignum]: https://github.com/awslabs/s2n-bignum

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

#### Dependency rules — decided: nine crates

A crate boundary is only a guarantee if the dependency graph is stated and enforced. The
allowed edges:

| Crate | May depend on | Must **not** depend on |
|---|---|---|
| `heyl-crypto` | the §2 crypto crates, `zeroize`, `region` | any runtime, any transport, **any `heyl-*`** |
| `heyl-domain` | `heyl-crypto`, `serde`, `serde_json`, `jiff`, `uuid` | any runtime, any transport, `heyl-proto`, `heyl-ports` |
| `heyl-vault` | `heyl-domain`, `heyl-crypto`, `serde_json`, `snap` | any runtime, any transport, `heyl-proto` |
| `heyl-ports` | `heyl-domain`, trait plumbing only (`async-trait`) | every adapter, `heyl-app`, `heyl-proto` |
| `heyl-app` | `heyl-domain`, `heyl-crypto`, `heyl-vault`, `heyl-ports` | **`heyl-platform`, `heyl-grpc`, `heyl-proto`, `tokio`** |
| `heyl-proto` | `tonic`, `tonic-web`, `prost`, `prost-types` | any other `heyl-*` |
| `heyl-grpc` | `heyl-proto`, `heyl-domain`, `heyl-ports`, `tokio`, `hyper`, `rustls` | `heyl-platform`, `heyl-app` |
| `heyl-platform` | `heyl-ports`, `heyl-domain`, `keyring`, `directories`, `crossterm`, `rpassword`, `qr2term`, `ctap-hid-fido2` | `heyl-app`, `heyl-grpc` |
| `heyl-cli` | everything — the only crate that wires adapters into the core | — |

Three edges do the real work. **`heyl-crypto`, `heyl-domain` and `heyl-vault` cannot reach the
network**, because they do not depend on a runtime or transport at all — not by convention, but
because the symbols do not exist. **`heyl-app` cannot see `heyl-platform` or `heyl-grpc`**, so it
is physically incapable of calling an OS API or constructing a request; composition happens once,
in `heyl-cli`. And **`heyl-crypto` depends on no `heyl-*` crate at all**, which is what lets it be
strictly deterministic and exhaustively fixture-tested. That is what makes the ports real rather
than decorative.

Enforce it in CI with a `cargo tree`-based check so a violation fails the build rather than
relying on review to catch a new dependency line. `cargo-deny` carries the complementary bans:
no `cc`, no `cmake`, no `*-sys` crate (with `libc` explicitly allowed), so M0's measured "pure
Rust" property is an invariant rather than an observation, and a dependency bump that quietly
introduces a C toolchain fails the build. `[graph] targets` scopes all of it to the platforms §7
ships, so the check reasons about the binaries we build rather than about every target Rust has.

`unsafe_code = "forbid"` is declared once in `[workspace.lints]`; each crate opts in with
`[lints] workspace = true`, so a crate that omits it is visible in its own manifest rather than
invisible in a missing attribute.

### Reused crates

Beyond the crypto and transport tables above. Download figures are a maturity signal, not an
endorsement; everything here gets pinned.

| Concern | Crate | Ver | Note |
|---|---|---|---|
| **Keychain** | `keyring` | 4.2 | macOS Keychain, Windows Credential Manager, Linux Secret Service, in one API. 24M downloads. Default (`v1`) features only — **not** `cli`, which pulls `db-keystore`, a *file-backed* credential store at odds with §3, plus a mock store. keyutils is available but `v1` hardcodes Secret Service on Linux, so using it would mean selecting the store ourselves — a behaviour change (session-scoped, lost on reboot), not a feature flag. |
| **Platform paths** | `directories` | 6.0 | XDG / Known Folder / macOS Standard Directories. |
| **CLI** | `clap` + `clap_complete` | 4.x | Parser and generated shell completions (M6). |
| **Hidden input** | `rpassword` | 7.5 | Recovery code entry without echo; unix, windows, macOS. |
| **Terminal** | `crossterm` | 0.29 | TTY capabilities. `std::io::IsTerminal` covers plain detection. |
| **QR** | `qr2term` | 0.3 | Terminal QR (M4). Encoding via `qrcode` if we need control over quiet zone/polarity. |
| **TOTP** | `totp-rs` | 6.0 | RFC 6238 (M6). |
| **Timestamps** | `jiff` | 0.2 | ISO 8601 — see the ordering constraint below. |
| **JSON** | `serde_json` (`preserve_order`) | 1.x | `preserve_order` is **required**, not optional — see below. |
| **UUID** | `uuid` | 1.x | heymerge element keys. |
| **Errors** | `thiserror` / `anyhow` | 2.x / 1.x | Typed in libraries, contextual in the binary. Per-crate enums; `heyl-app` owns the taxonomy §5's exit codes name, `heyl-cli` maps it to codes. **No error ever carries key, plaintext or ciphertext bytes** — but decrypt failures *are* distinguished (too-short / bad-length / authentication), because the padding-oracle argument for opacity does not apply to a client decrypting data it fetched, and M2/M3 are exactly where a failed decryption must be diagnosable. |
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

`keyring` and `directories` mean two of the five *platform* ports contain **no OS-specific code
of our own** — the adapter delegates. The ports stay, because they are what let us bind
`HeadlessSecretStore` for CI and fakes for tests, but they get thin.

The exception is `FidoDevice`. On Windows, non-elevated processes cannot claim FIDO HID devices
directly; access goes through the system `WebAuthn.dll` API instead. So M9 (FIDO2) and M11 (Windows)
intersect at exactly one place, and it is the one port where the Windows adapter is
real work rather than delegation. Sequence M9 before M11 and treat that as its known cost.

### Distribution channels

**Intel Macs are not supported.** Apple stopped selling them, `macos-26-intel` is the last runner
image GitHub will publish, and the fleet behind it is already unreliable enough to be useless as a
gate: the job that settled this spent 24 minutes in a release build its `aarch64` counterpart
finishes in one, on a graph that had passed the same tests 50 seconds earlier. Supporting a target
means being able to build and test it on every change, and that is no longer true here. macOS is
`aarch64` only, in §6's matrix and in `deny.toml`'s `[graph] targets` alike.

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
- **Publishing `heyl` means publishing all nine workspace crates**, since `cargo publish`
  rejects path dependencies without versions. Automate with `release-plz`; mark the eight library
  crates as internal with no API-stability guarantee in their READMEs.

The nine-crate split is kept regardless — see the dependency rules above. Collapsing to one
crate with modules would reduce compiler-checked guarantees to convention, which is a worse
trade than nine publishes.

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

### Sessions — decided, and implemented

```
heyl session create [<name>] [--display <name>] [--timeout 8h] [--strict]
                             [--auto-extend] [--unlock]
heyl session unlock [<name>]           # blocks until approved; --wait bounds it
heyl session lock   [<name>]           # drops the unlock and cancels a pending request
heyl session set    [<name>] <key> <value>
heyl session get    [<name>] [<key>]
heyl session remove [<name>] [--force]
heyl session list
```

A **slot** is a local name for one session. `HEYL_SESSION` or `--session` picks one; `default`
is the one you get when you say nothing. Slots exist so a human and an agent can hold opposite
policies on the same account at the same time — yours caching for the day, an agent's re-asking
every access — and so the phone can tell them apart, because the approval screen shows the
session's own name.

**One QR scan per session.** Minting a session from another one's unlock is possible
(`CreateChallenge` → sign with the seed → `CreateTokens`, no swipe) and deliberately unused:
this way every session's seed comes straight from the phone, and no session can conjure another.

Four settings, split by what they cost:

| Key | Where it lives | Cost |
|---|---|---|
| `display-name` | META vault, E2EE | **an unlock** — and it is the only string the phone shows |
| `timeout` | `unlock_time_limit_minutes` | none; works while locked |
| `strict` | `client_settings` | none |
| `auto-extend` | `client_settings` | none |

`icon` is not a setting: it is always `cli`, a device type heylogin's own app ships an icon for.
`get` never unlocks — it reports `display-name` as `<locked>` rather than reaching for the
phone, so reading state is always cheap.

`timeout` is server-enforced: the backend stops serving the unlock blob at the deadline, which
binds any client that discards the seed. Its floor is **one minute** (0 is refused,
`DomainError 20482`), and a grant lasts `min(max_expires_at, now + timeout)` from the moment of
approval — absolute, not sliding, unless `auto-extend` opts a slot into
`ExtendSessionUnlock`. `strict` is the client half: heyl drops its own unlock as the command
exits, so the next access asks again.

**What this buys, stated honestly.** Per-access approval constrains software that behaves —
heyl holds the seed for one invocation and zeroizes. It is not containment: any session you
unlock once has received the phone authenticator's seed, and a client that keeps it reads
everything afterwards, invisibly, whatever the timeout says (`HEYLOGIN_SPEC.md` §6, confirmed
live). Real revocation is deleting the *authenticator*, which rotates the seed — not locking,
and not deleting the session.

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

### `heyl api` — unsafe by construction, and not shipped

The commands above are the product. `heyl api` is not: it is heylogin's gRPC surface with the
safety taken off, and it exists because reverse-engineering a protocol needs a way to ask the
backend a question that no use case has been designed for yet.

**Every one of the 123 RPCs is reachable by name, with no guards.** `CreateTokens` with a
`BACKUP_CODE` signature performs the destructive recovery `heyl recovery` asks about — except
nothing asks. `heyl api derive` prints seeds and vault keys to the terminal. A curated denylist
over 123 methods, most of which nobody has studied, would give confidence proportional to the
curation rather than to the danger, so there is none. **Point it at a throwaway account.**

That is why it is gated twice: a **default-off cargo feature**, so `prost-reflect` and the
embedded descriptor are absent from the release dependency graph entirely (a property `cargo tree`
can check, which `cfg(debug_assertions)` would not give), and `hide = true` so it does not appear
in `--help` even in a build that has it.

Four subcommands. One makes a call; the other three are pure functions with no network at all,
and together they close the loop — a login is RPCs plus exactly two pieces of arithmetic:

```
heyl api call CreateChallenge '{"email":"…"}'      → challenge, secretSalt, Argon2 params
  heyl api sign-challenge --challenge … --salt …   → signature            (pure)
heyl api call CreateTokens '{…,"response":"…"}'    → access token
heyl api call Sync > sync.json                     → the account
  heyl api derive --sync sync.json --commits …     → seed, profile seeds, vault keys  (pure)
  heyl api decode --blob … --key …                 → a real heymerge document         (pure)
```

Nothing is ambient: no keychain is read, and the token is a field on the request. `heyl api call
Sync --token ''` reproduces `DomainError 30100` against the live backend and `--token bad`
reproduces 30420 — which is how M0 produced `tests/fixtures/protocol/sync-unauthenticated` and
`sync-bad-token` by hand, with a shell script.

`heyl api decode` stops at the serialization framing, because heymerge semantics and the content
schemas belong to the read path. That is deliberate: it exists to print the documents that work
will be designed against.

Output is **canonical protobuf-JSON** — bytes as base64, enums by name, camelCase `json_name`,
`Timestamp` as RFC 3339 — via `prost-reflect` over the same committed descriptor set. Not `serde`
derives on the generated types: those render every `bytes` field as an array of integers, and in
this schema the bytes are the interesting part. What you read matches what HEYLOGIN_SPEC.md says,
and what `heyl api call Sync` prints feeds straight back into `heyl api derive --sync`.

Retired by it: `heyl-fixtures probe-signing`, which existed to vary `client-type`, the
authenticator and the signature on one RPC. `heyl api call` varies all three on any of them.

### `run`

`heyl run --env-file .env.tpl -- <cmd>` resolves `heyl://<vault>/<item>/<field>`
references in the template into the child's environment. Secrets are passed via the environment
of the spawned process only — never written to disk, never in argv, never in shell history.

### QR rendering, and the SAS alternative (M4)

QR is needed by exactly one flow — phone-swipe login. FIDO2 (M9) and device-to-device unlock (M10)
need none. And once M10 lands, QR is a **once-per-machine onboarding step**, not a daily
interaction, which caps how much polish it warrants.

**But the QR may be the wrong half of this flow to build.** heylogin's Compliance Whitepaper §4.4
describes the pairing handshake as normally a QR scan, and then: *"As an alternative for devices
without a camera, a hash-commitment procedure with Short Authentication String is used."* A terminal
client is precisely a device without a camera — the QR here is a picture the *user's phone* scans off
our screen, which works, but the SAS variant (`login/flow/pushAuthenticator.ts`, `symKeyToSas`) is
the path heylogin designed for our situation and it adds mutual key confirmation the bare QR channel
does not have.

M4 should establish which of the two the phone actually accepts before committing to rendering
polish. If SAS works, a short comparable string beats a 37×19 block of half-block characters on
every terminal that has ever wrapped a line.

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

`heyl recovery` reads the code from `HEYL_RECOVERY_CODE`, a hidden prompt, or stdin — **never
argv**, and there is deliberately no `--code` flag to spell it into `ps` output or shell history.
It is a **top-level command, not under `login`**: it is not a sign-in, and a destructive operation
must not be reachable by someone who thinks they are logging in. `--confirm` skips the question;
`--email` is not secret and is an ordinary flag, falling back to `HEYL_EMAIL` and then a prompt.

M4 introduces `heyl login push`, which is the first time a command called "login" means what the
word means. There is no `heyl login` before then — a command that cannot work is worse than an
absent one. On a headless box with no
Secret Service, the `SecretStore` port is bound to `HeadlessSecretStore`, which reads
`HEYL_TOKEN` / `HEYL_SESSION_KEY` from the environment — an adapter swap, not a special
case threaded through the code.

The CLI warns loudly that a recovery code in CI is a standing master credential (§4: reusable,
not one-time, and it unlocks every vault).

---

## 6. Testing

| Layer | Approach | Evidence | Needs an account? |
|---|---|---|---|
| Primitives (§2) | Known-answer tests from libsodium/tweetnacl vectors; Argon2id from RFC 9106 | **authoritative** | No |
| KDF & key hierarchy (§3) | Fixed-seed snapshots, one per derivation, independently addressable | *regression only* — see below | No |
| Vault decode | Recorded commit blobs + their expected plaintext, checked in redacted | authoritative once captured | No |
| heymerge round-trip | Property test: parse → serialize preserves unknown keys byte-for-byte | authoritative | No |
| Error decoding | M0's recorded `.http` exchanges replayed against `status.rs` | authoritative | No |
| Framing | A gRPC-Web body built at chosen sizes and frame counts, through the transport seam | authoritative, and it can ask sizes a recording never happened to contain | No |
| Generated surface | Two shape tests — unary and server-streaming — plus the trait's completeness against the descriptor set | authoritative for the generator | No |
| Record ↔ replay | Round trip: record against a stub, replay the records, compare | authoritative | No |
| **Use cases** | `heyl-app` over `DomainApi<RecordedApi>` — **real heylogin messages, through the real mapping** | authoritative for everything but the context salts | No |
| Port adapters | Fake `SecretStore` / `Terminal` / `ProcessRunner` / `Clock` / `RandomSource`; the suite never touches a real keychain | — | No |
| End-to-end, live | `tools/heyl-fixtures` against a real account — a **tool**, never a test | authoritative | Yes |

**The corpus is the single description of an account.** Before it there were two
descriptions and neither was heylogin's: a 658-line hand-built account in `heyl-app`'s tests,
which could only ever confirm that our code agreed with itself, and a wire recording that no
layer above the transport could reach. Recording at `HeyloginApi` — prost messages, one file per
call — replaced both, and the vault documents in it are heylogin's own bytes.

Records are **pre-mapping**: they hold what the backend sent, not what we understood it to mean,
so a change to `map.rs` does not invalidate them and a record can be re-read as understanding
improves. A **situation** is a whole corpus on disk under `tests/fixtures/api/<name>/`,
materialised from `base/` by `heyl-fixtures derive`; `diff -r` against the base is the entire
difference from reality. Situations cover what no backend produces on demand — an expired unlock,
a token due for rotation, `DomainError 30460`.

Two rules keep it committable. **No token is ever written**: the bearer token is metadata on a
`Request<T>`, so the recorder sees it, and it is dropped at the point of recording rather than
redacted afterwards, because a redaction step that runs later is one that can be forgotten. And
**the corpus must open with the committed test code and with nothing else** — `rekey` asserts
both halves before writing, which is what catches a layer the re-key forgot.

**No automated test ever touches a real account.** The line is: tests replay recorded flows; only
`tools/` talks to heylogin. A live confirmation is a deliberate act someone performs, never a test
that could fire on its own — which keeps a standing master credential out of CI and keeps the suite
green or red for reasons that are about the diff. The cost is that nothing automated notices when
heylogin's behaviour drifts; only the next manual run does.

**The whole suite runs on every target that ships, not only on the machine that wrote it.**
`.github/workflows/ci.yml` builds a matrix of the five triples in `deny.toml`'s `[graph] targets`
— linux-musl and Windows-MSVC on `x86_64` and `aarch64`, and Apple on `aarch64` only — one native
GitHub runner per triple, no cross-linker anywhere. Each job runs `cargo test --workspace --all-features` in **debug**
(so `overflow-checks` stay on, which is the point for code that indexes and does arithmetic over key
material) and then a separate `--release -p heyl` build whose binary is uploaded as a workflow
artifact. `fmt` and `clippy` are host-independent and run once, beside the matrix rather than inside
it. All five are required checks: a target-specific break — a dependency gated to `cfg(unix)`, say —
fails the pull request that introduced it rather than being discovered whenever someone next tries
that platform. That is also the reason `.ship/gates.sh` no longer claims to mirror CI completely;
one machine cannot.

**Recorded flows replay at the wire, not at the port.** The fixtures are re-keyed response *bytes*
fed through the real adapter, because the two defects M2 actually shipped — a lock-mapping rule and
reading `DomainError` from the wrong `tonic` API — both lived in `heyl-grpc`, and one of them passed
green precisely because the test hand-built the `Status` the way the broken code read it. A
port-level fake cannot catch either, by construction. `heyl-app`'s own use-case tests keep using a
fake `HeylApi` with hand-built domain objects, where recorded bytes would only obscure things.

**Nothing that is or verifies a secret is ever committed.** The re-key replaces, rather than
redacts: the recovery code, the seed, `secretInfo.checksum` (it is `SHA512(seed)[:32]` — an offline
*verifier*, and publishing one hands out an oracle), the access token, the session private key, and
every blob that would decrypt to the seed under a committed key. The rule that makes it checkable:
the fixture must open with the committed **test** seed and with nothing else.

**The key-hierarchy row is weaker than the others, deliberately.** Nothing upstream covers
heylogin's *composition* — which context string, concatenated in which order, truncated where — so
a fixed-seed suite proves self-consistency, not agreement with heylogin. A mistyped context would
yield stable, self-consistent, wrong keys and the suite would stay green. Building a differential
oracle (running the shipped bundle as a reference) would cost more than the milestone it guards,
so instead the oracle is **staged through M2**:

- `CreateTokens` accepting our signature is backend confirmation of the seed derivation,
  `salt-authenticator-login-signing-key-`, the KDF and Ed25519;
- M2 additionally calls `Sync`/`ListCommits` and decrypts one vault, confirming the profile and
  vault limbs a milestone earlier than M3.

That is why the derivation snapshots are stored **one per link** rather than as a single blob: a
failure at M2 or M3 then names the link instead of pointing at "crypto". Authoritative vectors
live in `tests/fixtures/crypto/upstream/` as committed JSON and must never change silently;
regression values are `insta` snapshots, where a diff surfacing in `cargo insta review` is exactly
the intended signal.

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
| **M1** | **Crypto core** — workspace + CI, `heyl-crypto` (§2 primitives, `deriveSecretFromSeed`, every context salt v1 needs) and `heyl-domain` (ids, locks, `Timestamp`, the full key hierarchy) | *proven*: primitives vs upstream vectors, Argon2id vs RFC 9106. *pinned*: every derivation snapshotted per link, regression-only until M2. *enforced*: dependency-graph rules, no `unsafe`, no `cc`/`cmake`/`*-sys`. *built*: full hierarchy, `mlock`ed secret newtypes | M |
| **M2** | ✅ **`heyl recovery` + hierarchy confirmation** — `heyl-proto`/`heyl-grpc`/`heyl-ports`/`heyl-app`/`heyl-vault`/`heyl-platform`/`heyl-cli`, a self-granted unlock, and `heyl doctor`. The login method changed under it: recovery-code login turned out to be destructive and client-type-gated (§2), so the confirmation was reached with the **phone swipe** | Done: the shipped binary recovers a real account, stores the session in the OS keychain, and a separate `heyl doctor` invocation reports **37 passed, 0 failed** — all eight derivation links across four profiles, each byte-compared against the key heylogin publishes, and all five vaults decrypted | **L** |
| **M3** | ✅ **API surface + re-base** — `HeyloginApi` generated from the descriptor set (one method per RPC, all 123), a stateless `GrpcClient`, and `heyl-ports::HeylApi` re-implemented as `DomainApi<A: HeyloginApi>`. Adds the hidden `heyl api` behind a default-off cargo feature | Done: 123 methods generated and callable; a login is hand-drivable through `heyl api` (`call CreateChallenge` → `sign-challenge` → `call CreateTokens`); `recovery`, `doctor` and the offline suite green throughout; `prost-reflect` absent from the release graph | M/L |
| **M4** | ✅ **Corpus** — record and replay at `HeyloginApi` in prost messages: a generated `RecordingApi` decorator and `RecordedApi` stub, `session.json` migrated to messages, one full record per situation, and message-level re-keying | Done: `heyl-app`'s use cases run on real heylogin messages through the real mapping; `account.rs` (658 lines), the wire fixture, `wire_replay.rs` and the frame machinery are deleted; framing is tested in isolation at chosen sizes instead | M |

**Still to do, unplanned and unordered.** These were once numbered M3–M11 with drafted exit
criteria; that was a plan for work nobody had started, and re-deciding it step by step as each is
reached has been more useful than mechanically shifting the numbers. What remains:

- **Read path** — full sync, profile/vault enumeration, serialize + heymerge parse, selector
  resolution. `heyl api decode` already prints real documents to design the parser against.
- ~~**Phone swipe**~~ — done: `CreateLongPollChannelChallenge`, QR rendering behind the
  `Terminal` port, seed from the channel, `CreateTokens`. Polarity is exposed as `--qr`, because
  a code drawn for the wrong background renders perfectly and simply will not scan.
- ~~**Session registration**~~ — done: `SessionMetadata` write, tombstone on `session remove`,
  `session list`, and the phone-swipe pairing it needs. What is left is the read path using it.
- **UX completion** — `totp`, `run`, `completion`, output contract, exit codes, error taxonomy.
- **Distribution** — `cargo-dist` binaries, npm, PyPI.
- **Hardening** — zeroization audit, fuzz the vault decoder, threat-model review, crates.io.
- **FIDO2 login**, **device-to-device unlock**, **Windows support** — independent of one another
  and of the core, which is the intent behind the port boundary.

**Critical path: ~~M0~~ → ~~M1~~ → ~~M2~~ → ~~M3~~ → ~~M4~~ → read path.** M1 carried the correctness
risk but could not retire it: with no oracle available offline, **M2 is where the reverse
engineering was first confirmed**, which is why M2 reached past login to decrypt a vault.

M3 was inserted after M2 on the argument that the client had a use-case-shaped port and no
statement of what heylogin's API actually *is* — so every new capability meant designing a domain
method before anything could be tried. It also turned out to be the cheapest way to answer
questions that had been deferred: `heyl api` sends any of the 123 RPCs with any `client-type` and
any token, which is what `probe-signing` was written to do for one of them.

The first genuinely useful build is the **read path** — read-only, recovery-code login, no phone
flow. Worth dogfooding rather than waiting for hardening.

---

## 8. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| ~~Backend rejects an unofficial client~~ | **Closed** | Probed at M0: `client-type: 400` is accepted and `client-version` is not validated. Not a risk. |
| `tonic` / `tonic-web` API churn | Low | `tonic` is mature and widely deployed. `connectrpc` was built at full parity during M0 and works, so a switch back is a known quantity rather than a hope. |
| ~~`mlock` released on drop, unlocking pages under live secrets~~ | **Closed** | Present from M1 and invisible: `mlock` is page-granular, so dropping one 32-byte secret unlocked the page others were still using. Found by the cross-platform CI matrix (§6) — Windows' `VirtualUnlock` keeps no lock count and panicked; Linux and macOS had accepted it silently. Fixed by never releasing the lock (§3), with a `/proc/self/smaps` test that fails against the old behaviour. The general lesson is in §4: `region` locks pages, it does not own them. |
| ~~Static musl artifacts need a C cross-toolchain~~ | **Closed** | Found at M0 (`ring`/`aws-lc-sys` are C), retired at M2 by taking rustls' `CryptoProvider` from `rustls-graviola` instead. No `cc` or `cmake` on any shipped target, so `rustup target add` is enough. The new exposure is graviola itself — see §4. |
| graviola is a young TLS provider, and excludes pre-~2014 x86 and Raspberry Pi 4 and earlier | Medium | Adopted at M2 to keep §4's pure-Rust claim true of the whole binary. Written by rustls' author over formally-verified s2n-bignum assembly, and it secures only the transport — the vault crypto is `heyl-crypto`. Revisit if a user reports an unsupported CPU, or if `ring` ever ships a pure-Rust build. |
| ~~gRPC-Web streaming from a native client is untested~~ | **Downgraded** | The premise was wrong on two counts, found at M3 by parsing the descriptor set rather than reading method names. **`LongPollSync` is unary** despite its name, and so is `CreateLongPollChannelChallenge` — which is what the phone swipe actually calls. Of 123 methods **exactly one streams**, `SyncService/StreamingSync`, server-streaming, and nothing in the plan needs it (§2 lists realtime sync as a non-goal). It is generated and reachable as `heyl api call StreamingSync`, so the question can be answered in a minute rather than carried as a risk. |
| A context salt or KDF detail is subtly wrong | Medium | **M1's suite is *not* the guard** — a mistyped context yields stable, self-consistent, wrong keys and the suite stays green. The guard is M2: `CreateTokens` acceptance confirms the login limb, and M2's single vault decrypt confirms the profile/vault limb. Per-link snapshots make the failure name the link. |
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
