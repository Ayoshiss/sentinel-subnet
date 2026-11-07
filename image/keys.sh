#!/usr/bin/env bash
#
# Make the production Secure Boot keys for the miner image.
#
#     bash image/keys.sh ~/.config/sentinel/secureboot
#
# Whoever holds the db key decides what a Sentinel miner can boot, so:
#   - run it on the machine that will sign, never on a build VM;
#   - every private key is encrypted with a passphrase you type, and never
#     leaves that directory unencrypted;
#   - only the certificates are copied into the repo (image/secureboot/), since
#     validators and brokers need them to check a boot.
# docs/key-custody.md says who holds what and how a key is replaced.
set -euo pipefail
out=${1:?directory for the private keys}
repo=$(cd "$(dirname "$0")" && pwd)/secureboot

if [ -e "$out/db.key" ]; then
  echo "refusing: $out/db.key already exists. Keys are made once." >&2
  exit 1
fi
umask 077
mkdir -p "$out" "$repo"
chmod 700 "$out"

# RSA-2048: the size UEFI firmware is required to support. Larger keys are
# refused by some firmware, which would only show up as a miner that won't boot.
for n in PK KEK db; do
  echo "== $n: choose a passphrase (you will be asked to confirm it)"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -out "$out/$n.key"
  echo "== $n: enter the same passphrase to make the certificate"
  openssl req -new -x509 -key "$out/$n.key" -sha256 -days 3650 \
    -subj "/CN=Sentinel miner $n/O=Sentinel/" -out "$out/$n.crt"
  openssl x509 -in "$out/$n.crt" -outform DER -out "$out/$n.der"
  cp "$out/$n.crt" "$out/$n.der" "$repo/"
done
chmod 644 "$repo"/*

echo
echo "Private keys (encrypted): $out"
echo "Certificates for the repo: $repo"
openssl x509 -in "$out/db.crt" -noout -fingerprint -sha256
echo "Back up $out to offline storage now. Losing db.key means no new image can be signed."
