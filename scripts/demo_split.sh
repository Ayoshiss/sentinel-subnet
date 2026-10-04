#!/usr/bin/env bash
#
# Proof that the broker and the enclave are actually separate.
#
# Everything else in this repository tests the split inside one Python process,
# which is honest as far as it goes: the sockets are real and the refusals are
# real. What it cannot show is the property the whole product rests on, that the
# operator of the miner's host does not possess the database credential. A single
# process shares memory, so inside one you can only assert it.
#
# This runs two OS processes and checks their command lines, which is the
# difference between claiming custody and showing it.
#
# Four things happen, in order:
#
#   1. a broker starts holding a DSN
#   2. a miner starts holding none, attests, and is given one
#   3. an agent queries the miner and gets an attested answer
#   4. the same miner, one byte of measurement different, is refused and dies
#
# SIMULATION, in one respect that matters: with no /dev/sev-guest the chip is
# MockSilicon, signing in software. The custody separation shown here is real,
# the hardware root of trust is not. On a real SEV-SNP guest, drop
# --allow-mock/--mock-chip-seed and the broker verifies AMD's chain instead.
#
# Usage:  bash scripts/demo_split.sh
# Writes nothing outside a temp directory it removes on exit.

set -euo pipefail

cd "$(dirname "$0")/.."
PY="${PY:-.venv/bin/python}"
WORK="$(mktemp -d)"
BROKER_PORT="${BROKER_PORT:-8100}"
MINER_PORT="${MINER_PORT:-8101}"

# The stand-in for the real secret. A DSN is just a string, so this one is a
# sqlite path with a token in it: if the token ever appears in the miner's
# process, the split has failed and this script says so. Against a real database
# the same string would be "postgresql://role:password@host/db".
SECRET="pw-5f3a9c-do-not-leak"

DSN="sqlite:///$WORK/analytics-$SECRET.db"

cleanup() {
    [ -n "${BROKER_PID:-}" ] && kill "$BROKER_PID" 2>/dev/null || true
    [ -n "${MINER_PID:-}" ] && kill "$MINER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
# ps truncates the command line unless told not to, and a truncated command line
# would make "the secret is not there" true for the wrong reason. Step 5 is the
# control that would have caught it, and did.
cmdline() { ps -ww -o command= -p "$1"; }
ok()  { printf '  \033[32mOK\033[0m  %s\n' "$*"; }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; exit 1; }

# A fixed mock chip so the broker can trust it before the miner exists. Real
# silicon needs none of this: AMD's certificate chain identifies the chip.
SEED="$($PY -c 'import secrets; print(secrets.token_hex(32))')"
read -r CHIP PUBKEY <<<"$($PY - "$SEED" <<'PYEOF'
import sys
from sentinel.attestation import MockSilicon
seed = bytes.fromhex(sys.argv[1])
chip = MockSilicon.from_seed(seed, chip_id=f"MOCK-EPYC-{seed[:4].hex()}")
print(chip.chip_id, chip.public_verifier().public_key_hex)
PYEOF
)"

APPROVED="$($PY -c 'from sentinel.attestation import sha384; print(sha384(b"approved-image"))')"
TAMPERED="$($PY -c 'from sentinel.attestation import sha384; print(sha384(b"tampered-image"))')"

say "1. The broker starts, on what would be the customer's machine"
$PY scripts/run_broker.py \
    --scope "analytics=${DSN}" \
    --measurement "$APPROVED" \
    --allow-mock-chip "$CHIP=$PUBKEY" \
    --bind 127.0.0.1 --port "$BROKER_PORT" > "$WORK/broker.log" 2>&1 &
BROKER_PID=$!

for _ in $(seq 20); do
    curl -fsS -m 1 "http://127.0.0.1:$BROKER_PORT/health" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -fsS -m 2 "http://127.0.0.1:$BROKER_PORT/health" >/dev/null || bad "broker never came up"
ok "broker answering on port $BROKER_PORT, pid $BROKER_PID"
ok "it holds the secret: $(grep -c 'holding a secret' "$WORK/broker.log") scope(s)"

say "2. The miner starts holding no credential, and has to earn one"
KEY="$($PY scripts/make_api_key.py --label agent --keys "$WORK/keys.json" 2>/dev/null | grep -o 'sk_sentinel_[A-Za-z0-9_-]*')"
[ -n "$KEY" ] || bad "could not mint an API key"

$PY scripts/run_miner.py \
    --allow-mock --mock-chip-seed "$SEED" \
    --measurement "$APPROVED" \
    --broker-url "http://127.0.0.1:$BROKER_PORT" --broker-insecure \
    --scope analytics \
    --api-keys "$WORK/keys.json" \
    --bind 127.0.0.1 --port "$MINER_PORT" \
    --no-chain --allow-any --hotkey-ss58 5DemoSplitMiner > "$WORK/miner.log" 2>&1 &
MINER_PID=$!

for _ in $(seq 30); do
    curl -fsS -m 1 "http://127.0.0.1:$MINER_PORT/health" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -fsS -m 2 "http://127.0.0.1:$MINER_PORT/health" >/dev/null || {
    cat "$WORK/miner.log"; bad "miner never came up"; }
ok "miner answering on port $MINER_PORT, pid $MINER_PID"

# The claim, checked rather than asserted. The secret was never an argument to
# this process and never in its environment; it arrived over a socket, after a
# measurement check, into memory the operator would have to attach a debugger to
# read. That last part is what SEV-SNP makes impossible on real hardware.
if cmdline "$MINER_PID" | grep -q "$SECRET"; then
    bad "the secret is on the miner's command line"
fi
ok "the secret appears nowhere in the miner's command line"
if cmdline "$BROKER_PID" | grep -q "$SECRET"; then
    ok "the secret is on the broker's command line, where it belongs"
else
    bad "the broker does not hold the secret, so this proves nothing"
fi
grep -q "released 'analytics' to an attested enclave" "$WORK/broker.log" \
    && ok "broker log: released the credential to an attested enclave" \
    || bad "broker never released anything"

say "3. An agent queries the miner and gets an attested answer"
TOOLS="$(curl -fsS -m 10 "http://127.0.0.1:$MINER_PORT/tools" -H "Authorization: Bearer $KEY")"
echo "  tools visible to this key: $TOOLS" | head -c 300; echo
echo "$TOOLS" | grep -q 'analytics.query' \
    && ok "the tool is namespaced to the scope the broker released" \
    || bad "no analytics.query in the tool list"

NONCE="$($PY -c 'import secrets; print(secrets.token_hex(16))')"
ANSWER="$(curl -fsS -m 10 -X POST "http://127.0.0.1:$MINER_PORT/call" \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d "{\"tool\":\"analytics.query\",\"arguments\":{\"sql\":\"SELECT 1 AS live\"},\"nonce\":\"$NONCE\",\"request_id\":\"demo-split-1\"}")"
echo "$ANSWER" | head -c 400; echo
echo "$ANSWER" | grep -q '"attestation"' \
    && ok "the answer carries an attestation" \
    || bad "no attestation in the response"
echo "$ANSWER" | grep -q "$SECRET" && bad "the response leaked the credential"
ok "the response does not contain the credential"

say "4. The negative control: the same miner, a different image"
kill "$MINER_PID" 2>/dev/null || true
wait "$MINER_PID" 2>/dev/null || true
MINER_PID=""

set +e
$PY scripts/run_miner.py \
    --allow-mock --mock-chip-seed "$SEED" \
    --measurement "$TAMPERED" \
    --broker-url "http://127.0.0.1:$BROKER_PORT" --broker-insecure \
    --scope analytics \
    --bind 127.0.0.1 --port "$MINER_PORT" \
    --no-chain --allow-any --hotkey-ss58 5DemoSplitMiner > "$WORK/tampered.log" 2>&1
STATUS=$?
set -e

[ "$STATUS" -ne 0 ] && ok "the tampered miner exited $STATUS instead of serving" \
                    || bad "the tampered miner started, which is the failure this exists to catch"
grep -q "launch measurement mismatch" "$WORK/tampered.log" \
    && ok "refused for the right reason: $(grep -o 'launch measurement mismatch.*' "$WORK/tampered.log" | head -1)" \
    || { cat "$WORK/tampered.log"; bad "refused for some other reason"; }
curl -fsS -m 2 "http://127.0.0.1:$MINER_PORT/health" >/dev/null 2>&1 \
    && bad "something is still serving on the miner's port" \
    || ok "nothing is listening on port $MINER_PORT"
grep -q "$SECRET" "$WORK/tampered.log" && bad "the refusal leaked the credential"
ok "the refusal message does not contain the credential"

say "5. The control: what the default does instead"
# Without this step, step 2 proves very little. "The secret is not on the
# miner's command line" is only evidence if it would be there otherwise, so run
# the default self-brokering mode and look.
$PY scripts/run_miner.py \
    --allow-mock --mock-chip-seed "$SEED" \
    --measurement "$APPROVED" \
    --scope "analytics=sqlite:///$WORK/control-$SECRET.db" \
    --bind 127.0.0.1 --port "$MINER_PORT" \
    --no-chain --allow-any --hotkey-ss58 5DemoSelfBroker > "$WORK/selfbroker.log" 2>&1 &
MINER_PID=$!
for _ in $(seq 30); do
    curl -fsS -m 1 "http://127.0.0.1:$MINER_PORT/health" >/dev/null 2>&1 && break
    sleep 0.5
done
if ! curl -fsS -m 2 "http://127.0.0.1:$MINER_PORT/health" >/dev/null 2>&1; then
    cat "$WORK/selfbroker.log"; bad "the control miner did not start"
fi
if cmdline "$MINER_PID" | grep -q "$SECRET"; then
    ok "self-brokering: the secret IS on the miner's command line, as expected"
else
    bad "the control did not reproduce, so step 2 proves nothing"
fi
grep -q "releases credentials to itself" "$WORK/selfbroker.log" \
    && ok "and the miner warns about it at startup" \
    || bad "no warning logged in self-brokering mode"
kill "$MINER_PID" 2>/dev/null || true; wait "$MINER_PID" 2>/dev/null || true; MINER_PID=""

say "Broker log"
cat "$WORK/broker.log"

printf '\n\033[1;32mThe miner held no credential until it proved what it booted, and the\n'
printf 'process that checked the proof was not the process that wanted the secret.\033[0m\n'
