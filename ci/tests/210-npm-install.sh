#!/bin/bash

set -uo pipefail

cd "${NPM_SUBFOLDER}" || exit

echo -e "Start npm install\n"

rm -rf package-lock.json node_modules

npm install
