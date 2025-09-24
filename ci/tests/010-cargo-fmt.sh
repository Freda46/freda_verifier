#!/bin/bash
# shellcheck disable=SC2086
set -eo pipefail

cd "${RUST_SUBFOLDER}" || exit

# Running cargo fmt
echo "" && echo "=== Running cargo fmt --check ===" && echo ""
cargo $CARGOARGS fmt --check
