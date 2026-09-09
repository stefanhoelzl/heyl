# heyl

**Unofficial** command-line client for [heylogin](https://heylogin.com) — retrieve passwords,
TOTP codes and custom fields from your vault in a shell or a script.

> [!IMPORTANT]
> Not affiliated with, authorised by, or endorsed by heylogin. "heylogin" is a trademark of its
> respective owner. This is an independent reimplementation of the client protocol, built for
> interoperability, containing no code from heylogin's own clients. Do not report heylogin
> service issues here.

## Status

**Early implementation — M2 of 11 is done and confirmed against a real account.**
`heyl doctor` reports **37 passed, 0 failed**: all eight derivation links across
four profiles, each byte-compared against the key heylogin publishes, and all
five vaults decrypted. The reverse engineering is correct.

It is not usable as a password manager yet — reading logins is M3.

What the binary does today:

```sh
heyl recovery --email you@example.com   # recover access with a recovery code
heyl doctor                             # walk the key hierarchy, and decrypt every vault
```

`heyl recovery` is **not** a login — see below. A login arrives with M4's phone
swipe; the mechanism already exists in `tools/heyl-fixtures`.

| | |
|---|---|
| [`DESIGN.md`](DESIGN.md) | Architecture, security model, command surface, milestones M0–M11 |
| [`HEYLOGIN_SPEC.md`](HEYLOGIN_SPEC.md) | The protocol: client bundles, live probing, and heylogin's own whitepapers, marked by source |
| [`crates/heyl-crypto/`](crates/heyl-crypto/) | §2 primitives, `deriveSecretFromSeed`, the context salts — deterministic, `mlock`ed, no `unsafe` |
| [`crates/heyl-domain/`](crates/heyl-domain/) | Identifiers, locks, heymerge-compatible timestamps, the authenticator → profile → vault key chain |
| [`crates/heyl-ports/`](crates/heyl-ports/) | The port traits — the backend, keychain, terminal, clock, randomness |
| [`crates/heyl-app/`](crates/heyl-app/) | The use cases: login, unlock, doctor. No transport, no OS, no runtime |
| [`crates/heyl-grpc/`](crates/heyl-grpc/) | gRPC-Web adapter; the only crate that sees the generated types |
| [`crates/heyl-cli/`](crates/heyl-cli/) | The `heyl` binary and the composition root |
| [`descriptors/`](descriptors/) | The schema as a `FileDescriptorSet` — 19 services, 123 methods, extraction verified lossless |
| [`tests/fixtures/protocol/`](tests/fixtures/protocol/) | Recorded gRPC-Web exchanges: the happy path and three error shapes |
| [`tools/`](tools/) | Development tools. The only code here that talks to a real account |
| [`vendor/tonic-web/`](vendor/) | Upstream, with a one-line fix for dropped gRPC-Web trailers |

**What is established.** The primitives are checked against RFC 8032, RFC 4231
and FIPS 180-4 vectors. The composition — which context salt, concatenated in
which order, truncated where — is the part no offline test can settle, because
fixtures built with our own contexts stay green under a wrong one. That is why
`heyl doctor` exists: it derives each key and compares it against the public
half heylogin publishes. Run live, it passes on every link.

**There is no unattended login, and that is a protocol constraint rather than
missing work.** heylogin offers two ways in without a phone present, and neither
is available to a third-party client:

- **Recovery code** — using it makes the server *delete your push authenticator*
  and its locks (heylogin's Security Whitepaper §6.5.4; we confirmed it by
  losing one). `heyl recovery` therefore shows you what it is about to
  disconnect and asks first, and is named for what it is rather than hiding
  behind the word "login". It costs a phone pairing every time, so it is a way
  back in, not a way to run unattended.
- **A stored session** — the unlock expires the next day at 02:00, and the server
  deletes the blob after 30 hours regardless.

So a headless box needs a human swipe roughly daily. Device-to-device unlock
(M10) is the path that changes this.

The `.proto` sources are derived output and are not committed. To read the schema:

```sh
python3 -m venv .venv && ./.venv/bin/pip install protobuf
./.venv/bin/python tools/extract-protos.py render      # -> proto/*.proto (gitignored)
```

## What it will do

```sh
heyl get github.com --field password
heyl totp aws-prod
heyl list --format json | jq -r '.[].title'
heyl run --env-file .env.tpl -- terraform apply
```

Read-only by design: it never creates, edits or deletes logins. The single exception is
registering itself as a named, revocable device in your heylogin app.

## Security posture

The 32-byte seed that unlocks everything is **never stored at rest**. The keychain holds only a
session token and a session private key — neither decrypts anything on its own. Each invocation
fetches the backend's session-unlock blob, recovers the seed in memory, uses it, and zeroizes.

The backend stops serving that blob when the unlock expires, so heylogin's re-swipe control is
enforced server-side rather than trusted to this client. See [`DESIGN.md`](DESIGN.md) §3.

## License

[Apache-2.0](LICENSE). See [`NOTICE`](NOTICE).
