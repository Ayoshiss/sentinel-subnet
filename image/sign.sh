#!/usr/bin/env bash
#
# Sign the built UKI for Secure Boot and put it in the image's ESP.
#
#     bash image/sign.sh DB.key DB.crt      # sign here with sbsign
#     bash image/sign.sh SIGNED.efi         # or install a UKI signed elsewhere
#
# image/release.sh uses the second form: the key stays on the machine that
# signs, and only the signed file comes here.
#
# Separate from the build on purpose: whoever holds the db key decides what can
# boot, so the key never needs to be on a machine that builds, and anyone can
# check a published image against a rebuild without it. The signature is
# outside what Authenticode hashes, so the approved digest is unchanged.
set -euo pipefail
cd "$(dirname "$0")/mkosi.output"
if [ $# -eq 1 ]; then
  cp "$1" sentinel-miner.signed.efi
else
  key=${1:?db key}; cert=${2:?db certificate}
  sbsign --key "$key" --cert "$cert" --output sentinel-miner.signed.efi sentinel-miner.efi
fi
start=$(sfdisk --json sentinel-miner.raw | python3 -c '
import json, sys
t = json.load(sys.stdin)["partitiontable"]
esp = [p for p in t["partitions"] if p["type"].upper() == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"]
print(esp[0]["start"] * t.get("sectorsize", 512))')
mcopy -o -i "sentinel-miner.raw@@$start" sentinel-miner.signed.efi ::/EFI/BOOT/BOOTX64.EFI
python3 ../../scripts/tdx_eventlog.py image sentinel-miner.signed.efi | head -1
