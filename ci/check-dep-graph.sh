#!/usr/bin/env bash
# Enforce DESIGN.md §4's dependency rules.
#
# The crate boundaries are only a guarantee if a violation fails the build
# rather than relying on a reviewer to notice a new line in a manifest. Two
# edges do the real work:
#
#   * heyl-crypto depends on no heyl-* crate at all, which is what lets it be
#     strictly deterministic and exhaustively fixture-tested;
#   * nothing pure may reach a runtime or a transport -- not by convention, but
#     because the symbols do not exist.
set -euo pipefail

fail=0

# forbidden[crate] = "space separated packages that must not appear in its graph"
declare -A forbidden=(
  [heyl-crypto]="heyl-domain heyl-vault heyl-ports heyl-app heyl-proto heyl-grpc heyl-platform heyl-cli tokio hyper tonic prost reqwest"
  [heyl-domain]="heyl-vault heyl-ports heyl-app heyl-proto heyl-grpc heyl-platform heyl-cli tokio hyper tonic prost reqwest"
  [heyl-vault]="heyl-ports heyl-app heyl-proto heyl-grpc heyl-platform heyl-cli tokio hyper tonic prost reqwest"
  [heyl-ports]="heyl-app heyl-proto heyl-grpc heyl-platform heyl-cli"
  [heyl-proto]="heyl-crypto heyl-domain heyl-vault heyl-ports heyl-app heyl-grpc heyl-platform heyl-cli"
  [heyl-app]="heyl-proto heyl-grpc heyl-platform heyl-cli tokio hyper tonic"
  [heyl-grpc]="heyl-platform heyl-app"
  [heyl-platform]="heyl-app heyl-grpc"
)

for crate in "${!forbidden[@]}"; do
  if ! cargo metadata --no-deps --format-version 1 \
       | grep -q "\"name\":\"$crate\""; then
    continue          # not created yet; rules apply as each crate lands
  fi
  graph=$(cargo tree --package "$crate" --edges normal --prefix none --no-dedupe 2>/dev/null \
          | awk '{print $1}' | sort -u)
  violated=0
  for banned in ${forbidden[$crate]}; do
    if grep -qx "$banned" <<<"$graph"; then
      echo "FAIL  $crate must not depend on $banned  (DESIGN.md §4)" >&2
      violated=1
      fail=1
    fi
  done
  [ "$violated" -eq 0 ] && echo "ok    $crate"
done

# Every crate must opt in to the workspace lints, which is where
# `unsafe_code = "forbid"` is declared. A crate that omits it is visible here
# rather than invisible in a missing attribute.
# `tools/*` are development binaries, excluded from the release and from the
# publish set (DESIGN.md, M2 decision 23). They may depend on anything, exactly
# like heyl-cli -- but they still opt in to the workspace lints below.
for manifest in crates/*/Cargo.toml tools/*/Cargo.toml; do
  [ -e "$manifest" ] || continue
  if ! grep -Pzoq '\[lints\]\s*\nworkspace = true' "$manifest"; then
    echo "FAIL  $manifest does not opt in to [lints] workspace = true" >&2
    fail=1
  else
    echo "ok    $manifest opts in to the workspace lints"
  fi
done

exit $fail
