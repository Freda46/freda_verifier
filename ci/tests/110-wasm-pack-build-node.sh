#!/bin/bash

set -uo pipefail

cd "${WASM_SUBFOLDER}" || exit

echo -e "Start wasm-pack build\n"

wasm-pack build --target nodejs