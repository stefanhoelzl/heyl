# heyl

**Unofficial** command-line client for [heylogin](https://heylogin.com) — retrieve passwords,
TOTP codes and custom fields from your vault in a shell or a script.

> [!IMPORTANT]
> Not affiliated with, authorised by, or endorsed by heylogin. "heylogin" is a trademark of its
> respective owner. This is an independent reimplementation of the client protocol, built for
> interoperability, containing no code from heylogin's own clients. Do not report heylogin
> service issues here.

## Status

**Early implementation — the phone-swipe login and the session surface now work against a real
account.** Every derivation link is confirmed live against the key heylogin publishes, and every
vault decrypts; [`DESIGN.md`](DESIGN.md) §6 is where that evidence lives, and how it is produced.

It is not usable as a password manager yet — reading logins is the next milestone.

What the binary does today:

```sh
heyl session create                     # pair with a QR swipe, and register as a device
heyl session unlock                     # ask your phone, and wait for the approval
heyl session list                       # what this machine has, and whether it is unlocked
```

That is the whole of it. A handful of further commands — the raw gRPC surface, the hierarchy
walk, and recovery-code recovery — exist only in a build made with `--features dev`, because
they are there for reverse-engineering the protocol rather than for using a password manager.
[`tools/README.md`](tools/README.md) describes them.

A **session** is what your phone approves, and what it names when it asks. Each has its own
keys, its own unlock policy and its own entry in the heylogin app, so an agent and you can hold
opposite policies at once:

```sh
heyl session create claude-code --strict     # its own device, re-asks every access
HEYL_SESSION=claude-code heyl get github.com # your phone: "approve claude-code?"
```

The name on that approval screen is the **only** thing your phone shows about who is asking —
which is why sessions are named for their callers.

`heyl session create` is how you sign in. There is no `heyl login` yet, and no unattended one at
all — see below.

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
| [`crates/heyl-cli/tests/scenarios/`](crates/heyl-cli/tests/scenarios/) | The e2e suite: each file is a list of `heyl` invocations, the traffic they made, and what they printed |
| [`crates/heyl-grpc/tests/protocol/`](crates/heyl-grpc/tests/protocol/) | Recorded gRPC-Web exchanges: the happy path and three error shapes |
| [`tools/`](tools/) | Development tools, and the `--features dev` workbench. The only code here that talks to a real account |
| [`vendor/tonic-web/`](vendor/) | Upstream, with a one-line fix for dropped gRPC-Web trailers |

**What is established.** The primitives are checked against RFC 8032, RFC 4231
and FIPS 180-4 vectors. The composition — which context salt, concatenated in
which order, truncated where — is the part no offline test can settle, because
fixtures built with our own contexts stay green under a wrong one. That is why
the workbench has a command that derives each key and compares it against the
public half heylogin publishes. Run live, it passes on every link.

**There is still no unattended login, and that is a protocol constraint rather
than missing work.** heylogin offers two ways in without a phone present, and neither
is available to a third-party client:

- **Recovery code** — using it makes the server *delete your push authenticator*
  and its locks (heylogin's Security Whitepaper §6.5.4; we confirmed it by
  losing one). It costs a phone pairing every time, so it is a way back in
  rather than a way to run unattended — and it is a thing to do in heylogin's
  own app, not through a third-party client, which is why heyl's own recovery
  command is not in a release build.
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

The 32-byte seed that unlocks everything is **never stored at rest**. The keychain holds a
session token, a session private key and a session id — the first two decrypt nothing on their
own, and the third only names us. Each invocation
fetches the backend's session-unlock blob, recovers the seed in memory, uses it, and zeroizes.

The backend stops serving that blob when the unlock expires, so heylogin's re-swipe control is
enforced server-side rather than trusted to this client. See [`DESIGN.md`](DESIGN.md) §3.

## License

[Apache-2.0](LICENSE). See [`NOTICE`](NOTICE).
