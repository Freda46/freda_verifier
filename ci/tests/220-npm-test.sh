#!/bin/bash

set -uo pipefail

cd "${NPM_SUBFOLDER}" || exit

echo -e "Start npm tests\n"

npm test
