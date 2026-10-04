#!/usr/bin/env bash
#
# Does the SEV-SNP launch measurement cover the kernel command line?
#
# This settles a claim that two published documents depend on. The reasoning is
# that it does not: the boot chain here is shim, then GRUB, then the kernel, all
# read from the disk after launch, and the launch measurement is fixed at launch.
# Reasoning is not measurement, and this claim is load-bearing, so: change the
# command line, reboot, and look.
#
#   measurement unchanged  ->  the command line is NOT in the launch measurement.
#                              A dm-verity root hash carried there would be as
#                              forgeable as the filesystem it describes. T23 needs
#                              a different boot chain, not a flag.
#
#   measurement changed    ->  the command line IS measured, which would mean
#                              measured direct boot is in play after all, and a
#                              root hash there is anchored. T23 becomes tractable
#                              and the published documents need correcting again.
#
# Either answer is worth the reboot. The second would be very good news.
#
# Run ON the miner host, as root, in three phases:
#
#     sudo bash scripts/probe_measurement_scope.sh apply
#     sudo reboot
#     sudo bash scripts/probe_measurement_scope.sh check
#     sudo bash scripts/probe_measurement_scope.sh revert   # then reboot again
#
# What breaks if the measurement does change: every miner instance pins the
# approved measurement and exits rather than serving under a value nobody
# approved. That is correct behaviour, and `revert` plus a reboot restores it.
# The watchdog will not loop, because a miner that never starts gives curl a 000
# rather than a 503, and the watchdog only reboots on a latched 503.
#
# Safe to read the measurement while miners are serving, but only because
# concurrent access to the SEV firmware channel is locked across processes
# (/run/lock/sentinel-sev-guest.lock). Before 2026-10-04 this script would have
# disabled the VMPCK and taken the host down. Do not reintroduce that by running
# --print-measurement without the lock in place.

set -euo pipefail

PROBE_FILE=/etc/default/grub.d/99-sentinel-measurement-probe.cfg
PROBE_PARAM="sentinel.probe=1"
STATE=/var/lib/sentinel/measurement-probe-baseline
HEALTH=http://127.0.0.1:8091/health
VENV=/opt/sentinel/.venv/bin/python
REPO=/opt/sentinel

[ "$(id -u)" = "0" ] || { echo "run as root"; exit 2; }

read_measurement() {
    # Prefer the serving miner: it already holds the value and asking it costs
    # no firmware call at all.
    local body
    if body=$(curl -s -m 10 "$HEALTH" 2>/dev/null) && [ -n "$body" ]; then
        printf '%s' "$body" | "$VENV" -c \
            'import json,sys; print(json.load(sys.stdin).get("launch_measurement",""))' 2>/dev/null && return 0
    fi
    # Nothing serving, so ask the chip directly. Takes the same lock the miners
    # take, so this is safe even if one is mid-start.
    ( cd "$REPO" && "$VENV" scripts/run_miner.py --print-measurement 2>/dev/null \
        | tr -d '[:space:]' )
}

case "${1:-}" in
apply)
    mkdir -p "$(dirname "$STATE")"
    baseline=$(read_measurement)
    [ -n "$baseline" ] || { echo "could not read the current measurement; aborting"; exit 1; }
    printf '%s\n' "$baseline" > "$STATE"
    echo "baseline measurement recorded: $baseline"
    echo "current /proc/cmdline: $(cat /proc/cmdline)"

    if [ -e "$PROBE_FILE" ]; then
        echo "probe already applied at $PROBE_FILE"
    else
        # Appended in a 99- file so it sorts after 50-cloudimg-settings.cfg,
        # which otherwise overwrites GRUB_CMDLINE_LINUX_DEFAULT wholesale.
        cat > "$PROBE_FILE" <<EOF
# Temporary. Added by scripts/probe_measurement_scope.sh to find out whether the
# kernel command line is covered by the SEV-SNP launch measurement. An inert
# parameter: the kernel does not know it, logs that it is unknown, and boots.
# Remove with: $0 revert
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT $PROBE_PARAM"
EOF
        echo "wrote $PROBE_FILE"
    fi

    update-grub
    echo
    echo "now: sudo reboot      then: sudo bash $0 check"
    ;;

check)
    [ -f "$STATE" ] || { echo "no baseline recorded; run 'apply' first"; exit 2; }
    baseline=$(cat "$STATE")
    echo "cmdline now: $(cat /proc/cmdline)"
    if grep -q "$PROBE_PARAM" /proc/cmdline; then
        echo "probe parameter IS on the running kernel command line, good"
    else
        echo "probe parameter is ABSENT from the command line."
        echo "The experiment did not actually run: grub did not pick up the file."
        echo "Nothing is proven either way. Investigate before concluding anything."
        exit 1
    fi

    current=$(read_measurement)
    [ -n "$current" ] || { echo "could not read the measurement now; miners may be down"; exit 1; }

    echo
    echo "  baseline: $baseline"
    echo "  now:      $current"
    echo
    if [ "$baseline" = "$current" ]; then
        echo "UNCHANGED. The kernel command line is NOT in the launch measurement."
        echo "A dm-verity root hash carried there would be forgeable. T23 needs the"
        echo "boot chain to change, not a kernel parameter."
    else
        echo "CHANGED. The kernel command line IS in the launch measurement."
        echo "That means measured direct boot is in effect, a root hash carried on"
        echo "the command line is anchored, and T23 is tractable. The published"
        echo "documents understate what attestation covers and must be corrected."
        echo
        echo "Miners are failing closed against the old pinned value, which is"
        echo "correct. Revert and reboot, then decide deliberately whether to"
        echo "adopt the new measurement."
    fi
    ;;

revert)
    rm -f "$PROBE_FILE"
    update-grub
    echo "removed the probe; reboot to return to the measured baseline"
    ;;

*)
    sed -n '2,45p' "$0"
    exit 2
    ;;
esac
