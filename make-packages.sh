#!/bin/bash
#
# Build the Firefox .xpi and Chrome .zip packages from extension/.

set -euo pipefail

CWD="${BASH_SOURCE%/*}"
cd "${CWD}"

mkdir -p dist
rm -f dist/freereolen.xpi dist/freereolen-chrome.zip

(
  cd extension
  zip -r -X ../dist/freereolen.xpi . \
    -x '*.DS_Store' '*.swp' 'icons/icon.svg'
)

cp dist/freereolen.xpi dist/freereolen-chrome.zip

echo "Built:"
ls -la dist/
