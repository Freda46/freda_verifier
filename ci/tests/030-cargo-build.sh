#!/bin/bash
# shellcheck disable=SC2086
set -eo pipefail

cd "${RUST_SUBFOLDER}" || exit

echo "" && echo "=== Running cargo build ===" && echo ""
cargo $CARGOARGS build --release

echo "=== Running cargo build no_std ===" && echo ""
cargo $CARGOARGS build --no-default-features --release
