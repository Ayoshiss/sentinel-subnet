#!/usr/bin/env bash
#
# Build the measured miner image and print what validators approve.
#
#     sudo MKOSI=/opt/mkosi/bin/mkosi bash image/build.sh
#
# Needs mkosi 25.3 and network. Everything the image contains comes from the
# pinned Ubuntu snapshot and image/requirements.lock, and the toolchain itself
# is built from the same snapshot (ToolsTree), so the host only runs mkosi.
# Two builds of the same commit should print the same digest; if they do not,
# that is a bug in this build, not a property of it.
#
# The image comes out unsigned. image/sign.sh signs it for Secure Boot, which
# does not change the Authenticode digest a validator approves.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p mkosi.cache mkosi.output
"${MKOSI:-mkosi}" --force build
ls -l mkosi.output/
python3 ../scripts/tdx_eventlog.py image mkosi.output/sentinel-miner.efi
sha256sum mkosi.output/sentinel-miner.raw
