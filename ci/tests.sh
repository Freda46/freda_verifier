#!/bin/bash
# shellcheck disable=SC2046
set -euo pipefail

if ! command -v docker &> /dev/null ; then
  echo "You should have docker!"
  exit 1
fi

# absolute path to project from relative location of this script
workdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
# defaults if not provided via env
DOCKER_ORG="${DOCKER_ORG:-zencash}"
IMAGE_NAME="${IMAGE_NAME:-sc-ci-base}"
IMAGE_TAG="${IMAGE_TAG:-focal_rust-stable_latest}"
image="${DOCKER_ORG}/${IMAGE_NAME}:${IMAGE_TAG}"
export CARGO_AUDIT_EXIT_ON_ERROR="${CARGO_AUDIT_EXIT_ON_ERROR:-true}"
export NEED_CARGO_README="${NEED_CARGO_README:-true}"
export NEED_WASMPACK="${NEED_WASMPACK:-false}"
export NEED_NPM="${NEED_NPM:-false}"
export RUST_SUBFOLDER="${RUST_SUBFOLDER:-.}"
export WASM_SUBFOLDER="${WASM_SUBFOLDER:-.}"
export NPM_SUBFOLDER="${NPM_SUBFOLDER:-.}"
export PROTOBUF_VERSION="${PROTOBUF_VERSION:-none}"
export NODE_VERSION="${NODE_VERSION:---lts}"


# run tests in docker or natively
if [ -n "${TESTS:-}" ]; then
  if [ -n "${DOCKER_READONLY_USERNAME:-}" ] && [ -n "${DOCKER_READONLY_PASSWORD:-}" ]; then
    echo "$DOCKER_READONLY_PASSWORD" | docker login -u "$DOCKER_READONLY_USERNAME" --password-stdin
  fi
  docker run --rm -t -v "${workdir}:/build" -w /build \
    --entrypoint /build/ci/docker/entrypoint.sh \
    -v "${HOME}"/key.asc:/key.asc \
    -e TESTS \
    -e CARGO_AUDIT_EXIT_ON_ERROR \
    -e NEED_CARGO_README \
    -e NEED_WASMPACK \
    -e NEED_NPM \
    -e RUST_SUBFOLDER \
    -e WASM_SUBFOLDER \
    -e NPM_SUBFOLDER \
    -e PROTOBUF_VERSION \
    -e NODE_VERSION \
    -e LOCAL_USER_ID="$(id -u)" \
    -e LOCAL_GRP_ID="$(id -g)"\
    --pull always \
    --env-file <(env | grep -E '^(RUSTFLAGS=|CARGOARGS=|RUST_CROSS_TARGETS=|RUSTUP_TOOLCHAIN=).+$') \
    "${image}" ci/run_tests.sh
else
  echo "No test defined!"
  exit 1
fi
