#!/usr/bin/env bash
#
# Can a unified kernel image (UKI) anchor the whole boot chain on GCP Intel TDX?
#
# A UKI is one EFI binary carrying the kernel, the initrd and the command line.
# If the TDX firmware measures it as a whole, a dm-verity root hash placed in its
# command line is anchored in the signed quote, and so is everything the root
# filesystem holds. That is the fix for T23. This script is the guest side of the
# experiment that checks it; the result is in docs/results.md (2026-11-06).
#
# Run ON a throwaway TDX VM (c3-standard-4, --confidential-compute-type=TDX,
# Ubuntu 24.04), as root:
#
#     sudo bash probe_tdx_uki.sh setup
#     sudo bash probe_tdx_uki.sh build A /root/uki-A.efi
#     sudo bash probe_tdx_uki.sh install /root/uki-A.efi && sudo reboot
#     sudo bash probe_tdx_uki.sh capture uki-A
#
# install creates a boot entry pointing at the UKI and makes it the next boot.
# If the UKI fails to boot, the firmware falls through to the stock entry. Keep
# this script and its outputs out of /tmp, which a reboot clears.
#
# Offline analysis of the captured quotes and event logs: scripts/tdx_eventlog.py
set -euo pipefail
cmd=${1:?}; shift || true
ESP=/boot/efi
case "$cmd" in
setup)
  systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get -qq update
  DEBIAN_FRONTEND=noninteractive apt-get -qq install -y systemd-ukify systemd-boot-efi efibootmgr python3 >/dev/null
  ls /usr/lib/systemd/boot/efi/linuxx64.efi.stub
  efibootmgr -v || true
  ;;
build)  # build <marker> <outfile>
  m=$1; out=$2; k=$(uname -r)
  ukify build --linux=/boot/vmlinuz-$k --initrd=/boot/initrd.img-$k \
    --cmdline="root=LABEL=cloudimg-rootfs ro console=ttyS0,115200 panic=-1 sentinel.uki=$m" \
    --output="$out" >/dev/null
  sha256sum "$out"
  ;;
install)  # install <uki>: one-shot boot of the UKI via BootNext
  uki=$1
  mkdir -p $ESP/EFI/sentinel; cp "$uki" $ESP/EFI/sentinel/uki.efi; sync
  dev=$(findmnt -no SOURCE $ESP); disk=/dev/$(lsblk -no PKNAME "$dev"); part=$(cat /sys/class/block/$(basename "$dev")/partition)
  efibootmgr -b 0042 -B >/dev/null 2>&1 || true
  efibootmgr -c -b 0042 -d "$disk" -p "$part" -L sentinel-uki -l '\EFI\sentinel\uki.efi' >/dev/null
  efibootmgr -n 0042 | grep -E "BootNext|0042"
  ;;
capture)  # capture <label>: quote with a fresh nonce, plus the firmware event log
  label=$1; d=/sys/kernel/config/tsm/report/$label
  rmdir $d 2>/dev/null || true; mkdir $d
  head -c 64 /dev/urandom > /root/$label.nonce
  cat /root/$label.nonce > $d/inblob
  cat $d/outblob > /root/$label.quote
  python3 - /root/$label.quote /root/$label.nonce "$label" <<'PY'
import sys
q=open(sys.argv[1],'rb').read(); n=open(sys.argv[2],'rb').read()
B=48
print("label", sys.argv[3])
print("quote_bytes", len(q), "version", int.from_bytes(q[0:2],'little'), "tee_type", hex(int.from_bytes(q[4:8],'little')))
for name,o in [("MRTD",136),("RTMR0",328),("RTMR1",376),("RTMR2",424),("RTMR3",472)]:
    print(name, q[B+o:B+o+48].hex())
print("report_data_matches_nonce", q[B+520:B+584]==n)
PY
  cp /sys/firmware/acpi/tables/data/CCEL /root/$label.ccel
  echo "cmdline $(cat /proc/cmdline)"
  ;;
esac
