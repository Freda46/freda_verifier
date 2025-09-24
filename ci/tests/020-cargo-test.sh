#!/bin/bash
# shellcheck disable=SC2086
set -eo pipefail

cd "${RUST_SUBFOLDER}" || exit

# Running cargo tests
echo "" && echo "=== Running cargo tests ===" && echo ""
cargo $CARGOARGS test --all-features --release

echo "=== Running cargo tests no_std ===" && echo ""
cargo $CARGOARGS test --no-default-features --release

for feature in serde std bins; do 
    echo "=== Running cargo tests no_std but '${feature}' ===" && echo ""
    cargo $CARGOARGS test --no-default-features -F "${feature}" --release
done