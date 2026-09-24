#!/usr/bin/env bash
#
# Reboot a miner whose chip has stopped answering.
#
# A SEV-SNP guest can lose attestation permanently while the process keeps
# running. If a request to the AMD security processor times out, the kernel
# disables the VMPCK rather than risk reusing an IV, and nothing short of a
# reboot brings it back. Seen in production on 2026-09-24: rc -110 from the ASP,
# ten hours dead, /health answering 200 the whole time because it reported
# cached identity and never asked whether the chip still worked.
#
# /health now returns 503 once a GuestError has been latched, so this watches
# for that and reboots.
#
# The circuit breaker is the important part. A host with degraded hardware will
# fail again immediately after a reboot, and a watchdog without a limit turns
# that into a boot loop that looks like flapping rather than a broken machine.
# After MAX_REBOOTS inside the window it stops and leaves the miner down, which
# is louder and easier to diagnose than a VM rebooting every few minutes.

set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8091/health}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"

#: Consecutive failures before acting. One 503 can be a request that raced a
#: restart; several in a row is the chip.
FAILURES_BEFORE_REBOOT="${FAILURES_BEFORE_REBOOT:-3}"

MAX_REBOOTS="${MAX_REBOOTS:-2}"
WINDOW_SECONDS="${WINDOW_SECONDS:-3600}"
STATE_FILE="${STATE_FILE:-/var/lib/sentinel/watchdog-reboots}"

#: Set to 1 to log the reboot instead of performing it. The reboot path is the
#: one part that cannot be exercised safely on a machine you are sitting at.
DRY_RUN="${DRY_RUN:-0}"

mkdir -p "$(dirname "$STATE_FILE")"
touch "$STATE_FILE"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) watchdog: $*"; }

recent_reboots() {
    local now cutoff
    now=$(date +%s)
    cutoff=$((now - WINDOW_SECONDS))
    awk -v c="$cutoff" '$1 > c' "$STATE_FILE" | wc -l
}

prune() {
    local now cutoff
    now=$(date +%s)
    cutoff=$((now - WINDOW_SECONDS))
    awk -v c="$cutoff" '$1 > c' "$STATE_FILE" > "$STATE_FILE.tmp" || true
    mv "$STATE_FILE.tmp" "$STATE_FILE"
}

failures=0
while true; do
    # `|| echo` would append to whatever curl already printed, producing
    # "000000" and a comparison that never matches anything.
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$HEALTH_URL") || code="000"
    [ -n "$code" ] || code="000"

    if [ "$code" = "200" ]; then
        if [ "$failures" -gt 0 ]; then
            log "healthy again after $failures failed checks"
        fi
        failures=0
        sleep "$CHECK_INTERVAL"
        continue
    fi

    failures=$((failures + 1))
    log "health returned $code ($failures/$FAILURES_BEFORE_REBOOT)"

    if [ "$failures" -lt "$FAILURES_BEFORE_REBOOT" ]; then
        sleep "$CHECK_INTERVAL"
        continue
    fi

    # 000 means the miner is not listening at all, which systemd already handles
    # by restarting the unit. Rebooting the host for that would be a large
    # hammer for a small problem, so only a latched 503 justifies it.
    if [ "$code" != "503" ]; then
        log "not a 503, leaving the host alone; systemd restarts the service"
        failures=0
        sleep "$CHECK_INTERVAL"
        continue
    fi

    prune
    count=$(recent_reboots)
    if [ "$count" -ge "$MAX_REBOOTS" ]; then
        log "ALREADY REBOOTED $count TIMES IN $((WINDOW_SECONDS / 60)) MINUTES."
        log "Refusing to reboot again. The host or its security processor is"
        log "probably degraded; move the miner to another host. Leaving it down,"
        log "because a boot loop hides this and a dead miner does not."
        sleep "$WINDOW_SECONDS"
        failures=0
        continue
    fi

    date +%s >> "$STATE_FILE"
    if [ "$DRY_RUN" = "1" ]; then
        log "DRY RUN: would reboot now (attestation dead, reboot is the only fix)"
    else
        log "attestation is dead and only a reboot clears it; rebooting now"
        systemctl reboot
    fi
    sleep "$CHECK_INTERVAL"
done
