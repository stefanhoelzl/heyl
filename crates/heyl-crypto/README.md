# heyl-crypto

heylogin's cryptographic primitives and key derivation.

**Internal to [`heyl`](https://github.com/stefanhoelzl/heyl). No API stability
guarantee** — it is published only because `cargo publish` rejects path
dependencies without versions.

The primitives are checked against RFC 8032, RFC 4231 and FIPS 180-4 vectors.
The heylogin-specific *composition* — which context, concatenated in which
order, truncated where — is not verified against heylogin by anything in this
crate and cannot be offline; see `DESIGN.md` §6.

`unsafe_code = "forbid"`. That covers this crate's own code, not its
dependencies.
