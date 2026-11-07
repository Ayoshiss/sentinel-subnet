#!/usr/bin/env bash
#
# Cut a miner image release. Run on the machine that holds the db key.
#
#     bash image/release.sh build                 # build HEAD on the build VM (~1 hour)
#     bash image/release.sh sign <keydir>         # sign here, write the disk there
#     bash image/release.sh image <name>          # make the GCP image
#
# The build VM never sees a private key. It builds the unsigned image from a
# committed tree, this machine downloads the UKI, signs it with the passphrase-
# protected db key (image/keys.sh), checks the signature left the approved digest
# unchanged, and sends back only the signed file. The GCP image then carries
# the certificates from image/secureboot/, which are public.
#
# Settings: ZONE (us-central1-a), BUILDER (sentinel-image-builder), OUT_DISK
# (sentinel-image-out).
set -euo pipefail
ZONE=${ZONE:-us-central1-a}
BUILDER=${BUILDER:-sentinel-image-builder}
OUT_DISK=${OUT_DISK:-sentinel-image-out}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
remote_out=/build/sentinel/image/mkosi.output

ssh_builder() { gcloud compute ssh "$BUILDER" --zone="$ZONE" --quiet --command="$1"; }

digest_of() { python3 "$repo/scripts/tdx_eventlog.py" image "$1" | head -1 | awk '{print $NF}'; }

cmd=${1:-}
case "$cmd" in
build)
  # A release is built from a commit, so anyone can rebuild the same one.
  if [ -n "$(git -C "$repo" status --porcelain)" ]; then
    echo "refusing: commit first, a release is built from a committed tree" >&2; exit 1
  fi
  commit=$(git -C "$repo" rev-parse HEAD)
  tarball=$(mktemp -t sentinel-release).tgz
  git -C "$repo" archive --format=tar.gz -o "$tarball" HEAD
  if ! gcloud compute instances describe "$BUILDER" --zone="$ZONE" \
       --format='value(disks[].source)' | grep -q "/$OUT_DISK"; then
    gcloud compute instances attach-disk "$BUILDER" --disk="$OUT_DISK" --zone="$ZONE"
  fi
  gcloud compute instances start "$BUILDER" --zone="$ZONE" --quiet
  # A VM that has just started takes a minute or two before it accepts SSH.
  sent=
  for _ in $(seq 18); do
    if gcloud compute scp --zone="$ZONE" --quiet "$tarball" "$BUILDER:/tmp/release.tgz" 2>/dev/null; then
      sent=1; break
    fi
    sleep 10
  done
  rm -f "$tarball"
  [ -n "$sent" ] || { echo "could not reach $BUILDER over SSH" >&2; exit 1; }
  ssh_builder "sudo sh -c 'set -e; rm -rf /build/sentinel.new; mkdir -p /build/sentinel.new; \
    tar xzf /tmp/release.tgz -C /build/sentinel.new; \
    if [ -d /build/sentinel/image/mkosi.cache ]; then mv /build/sentinel/image/mkosi.cache /build/sentinel.new/image/; fi; \
    rm -rf /build/sentinel; mv /build/sentinel.new /build/sentinel; echo $commit > /build/sentinel/COMMIT; \
    nohup env MKOSI=/opt/mkosi/bin/mkosi bash /build/sentinel/image/build.sh > /build/build.log 2>&1 &'"
  echo "building $commit on $BUILDER; follow with:"
  echo "  gcloud compute ssh $BUILDER --zone=$ZONE --command='tail -f /build/build.log'"
  ;;
sign)
  keys=${2:?directory holding db.key and db.crt}
  work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
  gcloud compute instances start "$BUILDER" --zone="$ZONE" --quiet
  sleep 30
  gcloud compute scp --zone="$ZONE" --quiet "$BUILDER:$remote_out/sentinel-miner.efi" "$work/unsigned.efi"
  before=$(digest_of "$work/unsigned.efi")
  echo "unsigned UKI digest: $before"
  echo "enter the db key passphrase:"
  osslsigncode sign -askpass -h sha256 -certs "$keys/db.crt" -key "$keys/db.key" \
    -in "$work/unsigned.efi" -out "$work/signed.efi" >/dev/null
  after=$(digest_of "$work/signed.efi")
  if [ "$before" != "$after" ]; then
    echo "refusing: signing changed the approved digest ($after)" >&2; exit 1
  fi
  osslsigncode verify -CAfile "$keys/db.crt" -in "$work/signed.efi" >/dev/null
  gcloud compute scp --zone="$ZONE" --quiet "$work/signed.efi" "$BUILDER:/tmp/sentinel-miner.signed.efi"
  ssh_builder "sudo sh -c 'set -e; cd /build/sentinel/image; bash sign.sh /tmp/sentinel-miner.signed.efi; \
    dd if=mkosi.output/sentinel-miner.raw of=/dev/disk/by-id/google-$OUT_DISK bs=4M conv=fsync status=none; sync'"
  echo "signed and written. approved digest: $after"
  echo "commit: $(ssh_builder 'cat /build/sentinel/COMMIT')"
  ;;
image)
  name=${2:?image name, e.g. sentinel-miner-v1}
  gcloud compute instances stop "$BUILDER" --zone="$ZONE" --quiet
  gcloud compute instances detach-disk "$BUILDER" --disk="$OUT_DISK" --zone="$ZONE" --quiet
  gcloud compute images create "$name" --source-disk="$OUT_DISK" --source-disk-zone="$ZONE" \
    --platform-key-file="$here/secureboot/PK.der" \
    --key-exchange-key-file="$here/secureboot/KEK.der" \
    --signature-database-file="$here/secureboot/db.der" \
    --guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE
  echo "image $name ready. Boot it with --confidential-compute-type=TDX --shielded-secure-boot."
  ;;
*)
  sed -n '3,9p' "$0"; exit 2
  ;;
esac
