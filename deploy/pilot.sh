#!/usr/bin/env bash
#
# Run a pilot's Sentinel machine on Google Cloud Intel TDX.
#
#     bash deploy/pilot.sh ip   <name>              # reserve the address first
#     bash deploy/pilot.sh up   <name> [options]    # boot the measured image
#     bash deploy/pilot.sh logs <name>              # what the image printed
#     bash deploy/pilot.sh down <name>              # delete the machine, rule, address
#
# The customer runs the key server (docs/pilot-install.md). Order matters:
#
#   1. `ip` reserves the machine's address. The customer gives it to their key
#      server as --tls-name, so the certificate it issues names this machine,
#      and allows it through to the key server's port.
#   2. The customer starts the key server and sends back its URL, the digest of
#      their agent's API key, their checker address (check_miner prints it on
#      first run) and the range their agent connects from.
#   3. `up` boots the measured image with those values. It holds no secret:
#      every value it is given is one the operator may see.
#
# Options for `up`:
#   --broker-url URL       the customer's key server (required)
#   --api-key LABEL=DIGEST from scripts/make_api_key.py (required, repeatable)
#   --allow CIDR           where the agent connects from (required, repeatable)
#   --checker ADDRESS      the customer's check_miner address (repeatable)
#   --scope NAME           a scope the key server holds (repeatable)
#
# Settings: ZONE (us-central1-a), IMAGE (newest gcp-tdx entry in
# measurements.json), IMAGE_PROJECT (this project), MACHINE (c3-standard-4).
set -euo pipefail
ZONE=${ZONE:-us-central1-a}
REGION=${ZONE%-*}
MACHINE=${MACHINE:-c3-standard-4}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
py="$repo/.venv/bin/python"; [ -x "$py" ] || py=python3

die() { echo "$*" >&2; exit 1; }
name_ok() { [[ $1 =~ ^[a-z][a-z0-9-]{0,30}$ ]] || die "name must be lowercase letters, digits and dashes"; }

cmd=${1:-}; name=${2:-}
[ -n "$cmd" ] && [ -n "$name" ] || { sed -n 3,8p "$0"; exit 2; }
name_ok "$name"
vm="sentinel-pilot-$name"

# The newest approved TDX release, unless IMAGE says otherwise.
release() {
  "$py" - "$repo/measurements.json" "${IMAGE:-}" <<'EOF'
import json, sys
data = json.load(open(sys.argv[1]))
want = sys.argv[2]
tdx = [m for m in data["measurements"] if m["platform"] == "gcp-tdx"]
pick = [m for m in tdx if m["image"] == want] if want else tdx[:1]
if not pick:
    sys.exit(f"no gcp-tdx release {want!r} in measurements.json")
print(pick[0]["image"], pick[0]["measurement"])
EOF
}

case "$cmd" in
ip)
  if ! gcloud compute addresses describe "$vm" --region="$REGION" >/dev/null 2>&1; then
    gcloud compute addresses create "$vm" --region="$REGION" --quiet
  fi
  ip=$(gcloud compute addresses describe "$vm" --region="$REGION" --format='value(address)')
  echo "address: $ip"
  echo "send the customer: start the key server with --tls-name $ip, and let $ip reach its port"
  ;;
up)
  shift 2
  broker=; keys=(); allow=(); checkers=(); scopes=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --broker-url) broker=$2; shift 2 ;;
      --api-key) keys+=("$2"); shift 2 ;;
      --allow) allow+=("$2"); shift 2 ;;
      --checker) checkers+=("$2"); shift 2 ;;
      --scope) scopes+=("$2"); shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -n "$broker" ] || die "--broker-url is required"
  [ ${#keys[@]} -gt 0 ] || die "--api-key is required: the agent has no other way in"
  [ ${#allow[@]} -gt 0 ] || die "--allow is required: say where the agent connects from"
  ip=$(gcloud compute addresses describe "$vm" --region="$REGION" --format='value(address)' 2>/dev/null) \
    || die "no address yet: run 'pilot.sh ip $name' and give it to the customer first"
  read -r image measurement < <(release)
  meta=$(mktemp); trap 'rm -f "$meta"' EXIT

  # The miner never signs with its hotkey (answers are signed by the chip), so
  # a pilot's hotkey is only a name. A fresh one per pilot, secret discarded.
  # The customer's checker must be allowed, or the machine refuses to start
  # with nobody able to check it; without one, the agent's API key still works
  # and the allow list holds only the throwaway address.
  "$py" - "$meta" "$repo/image/secureboot/db.der" "$repo/measurements.json" "$measurement" \
      "$broker" "${#keys[@]}" "${keys[@]}" "${#checkers[@]}" "${checkers[@]+"${checkers[@]}"}" \
      "${scopes[@]+"${scopes[@]}"}" <<'EOF'
import base64, json, sys
from bittensor.sp_core import Keypair

out, cert, registry, measurement, broker = sys.argv[1:6]
rest = sys.argv[6:]
n = int(rest[0]); keys = rest[1:1 + n]; rest = rest[1 + n:]
n = int(rest[0]); checkers = rest[1:1 + n]; scopes = rest[1 + n:]

api_keys = {}
for item in keys:
    label, sep, digest = item.partition("=")
    if not sep:
        sys.exit(f"--api-key {item!r}: expected LABEL=DIGEST")
    api_keys[label] = digest

hotkey = Keypair.create_from_mnemonic(Keypair.generate_mnemonic()).ss58_address
config = {
    "hotkey_ss58": hotkey,
    "measurement": measurement,
    "tdx_mrtd": json.load(open(registry))["tdx"]["mrtd"],
    "tdx_db_cert_b64": base64.b64encode(open(cert, "rb").read()).decode(),
    "broker_url": broker,
    "api_keys": api_keys,
    "allow_hotkey": checkers or [hotkey],
}
if broker.startswith("http://"):
    config["broker_insecure"] = True  # the credential is sealed to the enclave either way
if scopes:
    config["scope"] = scopes
json.dump(config, open(out, "w"))
print(f"miner hotkey: {hotkey}")
EOF

  # Only the customer's agent ranges reach the miner's port.
  gcloud compute firewall-rules delete "$vm" --quiet >/dev/null 2>&1 || true
  gcloud compute firewall-rules create "$vm" --allow=tcp:8091 --target-tags="$vm" \
    --source-ranges="$(IFS=,; echo "${allow[*]}")" --quiet >/dev/null 2>&1

  # Standard provisioning, not spot: a pilot must not be preempted.
  project_flag=(); [ -n "${IMAGE_PROJECT:-}" ] && project_flag=(--image-project="$IMAGE_PROJECT")
  gcloud compute instances create "$vm" --zone="$ZONE" --machine-type="$MACHINE" \
    --confidential-compute-type=TDX --shielded-secure-boot --maintenance-policy=TERMINATE \
    --image="$image" "${project_flag[@]+"${project_flag[@]}"}" --address="$ip" \
    --no-service-account --no-scopes --tags="$vm" \
    --metadata-from-file=sentinel-miner="$meta" --quiet >/dev/null
  echo "booting $image ($measurement)"

  # The image has no shell; the serial console is the only view in.
  for _ in $(seq 45); do
    sleep 10
    log=$(gcloud compute instances get-serial-port-output "$vm" --zone="$ZONE" 2>/dev/null || true)
    if grep -aq "Security Violation\|metadata refused\|Traceback" <<<"$log"; then
      grep -a "Security Violation\|metadata refused\|Error\|refused" <<<"$log" | tail -5
      die "the machine did not start; see 'pilot.sh logs $name'"
    fi
    if grep -aq "miner serving https" <<<"$log"; then
      grep -a "released\|TLS cert\|miner serving" <<<"$log" | tail -3
      echo
      echo "MCP endpoint: https://$ip:8091/mcp"
      echo "the customer checks it with scripts/check_miner.py --url https://$ip:8091 (docs/pilot-install.md step 6)"
      exit 0
    fi
  done
  die "not serving after 7 minutes; see 'pilot.sh logs $name'"
  ;;
logs)
  gcloud compute instances get-serial-port-output "$vm" --zone="$ZONE" 2>/dev/null \
    | grep -a "sentinel\|tdx: \|Security Violation\|released\|miner serving\|refused" | tail -40
  ;;
down)
  gcloud compute instances delete "$vm" --zone="$ZONE" --quiet 2>/dev/null || true
  gcloud compute firewall-rules delete "$vm" --quiet 2>/dev/null || true
  gcloud compute addresses delete "$vm" --region="$REGION" --quiet 2>/dev/null || true
  echo "$vm removed"
  ;;
*)
  sed -n 3,8p "$0"; exit 2
  ;;
esac
