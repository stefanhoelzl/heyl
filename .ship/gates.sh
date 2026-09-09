#!/usr/bin/env bash
# Local gate for /ship. Mirrors the PR-triggered jobs in .github/workflows/ci.yml,
# so a merge cannot be blocked by something this did not already catch.
#
# Deliberately NOT here: `cargo deny check advisories bans licenses sources`.
# It stays a CI concern because it changes when the RUSTSEC database changes
# rather than when your diff does -- a local run would pass or fail for reasons
# unrelated to what is being shipped, and installing the binary costs minutes
# inside a gate budget capped at 10.
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
