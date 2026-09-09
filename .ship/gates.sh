#!/usr/bin/env bash
# Local gate for /ship. Mirrors the PR-triggered jobs in .github/workflows/ci.yml,
# so a merge cannot be blocked by something this did not already catch.
set -euo pipefail

# The eight snapshots under crates/heyl-domain/tests/snapshots/ are the only
# regression detector for the key hierarchy until M2 confirms it against the
# backend (DESIGN.md §6). `INSTA_UPDATE=always` in a developer's shell would
# rewrite them and pass green, silently destroying that guard -- so the gate
# pins the variable rather than inheriting it.
export INSTA_UPDATE=no

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

# DESIGN.md §4's crate edges, and the `[lints] workspace = true` opt-in that
# carries `unsafe_code = "forbid"`. A stray dependency line compiles fine, so
# this is the check most likely to catch a real architectural mistake.
./ci/check-dep-graph.sh

# `bans licenses sources` -- the three that are a pure function of the diff.
# They were left to CI until M2 shipped the first TLS stack and both failed on
# the PR: `cc` via `ring`, and a wasm32-only crate under a licence not in the
# allow-list. Nothing about that needed a network round trip to discover.
#
# `advisories` is deliberately still absent: it changes when the RUSTSEC
# database changes rather than when your diff does, so a local run would fail
# for reasons unrelated to what is being shipped. CI runs all four.
if ! command -v cargo-deny >/dev/null 2>&1; then
    echo "cargo-deny is not installed, and this gate cannot vouch for the" >&2
    echo "dependency graph without it:" >&2
    echo "    cargo install cargo-deny --locked" >&2
    exit 1
fi
cargo deny check bans licenses sources
