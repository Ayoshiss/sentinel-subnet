#!/usr/bin/env bash
#
# Provision a small always-on VM on GCP and install the Sentinel validator.
#
#   PROJECT=my-gcp-project ./deploy/provision-validator-gcp.sh
#
# Nothing confidential is needed here. A validator checks attestations rather
# than producing them, so there is no SEV-SNP requirement, no N2D, and no
# scarce-capacity zone to hunt for. Any always-on Linux box works, and this
# script picks the smallest one Google rents.
#
# Why a VM at all, rather than a laptop: after activity_cutoff, 5000 blocks or
# about 16h40m, a validator that has set no weights counts as inactive, and the
# miners it was scoring drop to zero incentive because nothing else is weighting
# them. A laptop sleeps, so a laptop validator goes inactive overnight, and the
# subnet shows zero active neurons to anyone who looks at it.

set -euo pipefail

PROJECT="${PROJECT:?set PROJECT to your own GCP project id}"

# e2-micro in us-west1, us-central1 or us-east1 is on GCP's always-free tier,
# one instance per month. Anywhere else and this is a small bill rather than no
# bill. us-central1 by default because that is where SEV-SNP miners tend to be,
# and scoring latency should be measured from somewhere representative.
ZONE="${ZONE:-us-central1-a}"
MACHINE="${MACHINE:-e2-micro}"
NAME="${NAME:-sentinel-validator-1}"

# The free tier covers 30GB-months of *standard* persistent disk. pd-balanced
# is not included, so the default here is deliberate and changing it starts a
# bill that is easy to miss.
DISK_SIZE="${DISK_SIZE:-20GB}"
DISK_TYPE="${DISK_TYPE:-pd-standard}"

echo "project  $PROJECT"
echo "zone     $ZONE"
echo "instance $NAME ($MACHINE)"
echo

# No firewall rule. A validator opens outbound connections to miners and to the
# chain and listens for nothing, so it needs no ingress at all. If you find
# yourself opening a port on this machine, something is wrong.

echo "creating instance"
gcloud compute instances create "$NAME" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --machine-type="$MACHINE" \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size="$DISK_SIZE" \
    --boot-disk-type="$DISK_TYPE" \
    --tags=sentinel-validator \
    --metadata-from-file=startup-script="$(dirname "$0")/validator-startup.sh"

cat <<EOF

instance up.

The startup script installed the code and left the validator stopped, because
the one thing it needs cannot come from here: a wallet hotkey.

1. Copy the HOTKEY across. Two named files, never the folder.

     W=~/.bittensor/wallets/<wallet>
     gcloud compute scp --project=$PROJECT --zone=$ZONE \\
       \$W/coldkeypub.txt \$W/hotkeys/<hotkey> $NAME:/tmp/

   Copying the directory and deleting the coldkey afterwards is not the same
   thing: the encrypted coldkey would reach this disk before being removed, and
   rm does not erase it. Name the two files instead. coldkeypub.txt is a public
   key; the hotkey file is the only secret here, and it is NOT encrypted, so
   treat it as a bearer token.

     gcloud compute ssh $NAME --project=$PROJECT --zone=$ZONE --command \\
       'sudo install -d -m 0700 -o sentinel -g sentinel \\
          /home/sentinel/.bittensor/wallets/<wallet>/hotkeys && \\
        sudo install -m 0600 -o sentinel -g sentinel /tmp/coldkeypub.txt \\
          /home/sentinel/.bittensor/wallets/<wallet>/ && \\
        sudo install -m 0600 -o sentinel -g sentinel /tmp/<hotkey> \\
          /home/sentinel/.bittensor/wallets/<wallet>/hotkeys/ && \\
        rm -f /tmp/coldkeypub.txt /tmp/<hotkey>'

   Weights are signed by the hotkey, never the coldkey, which is why this runs
   unattended with no password. Someone who takes this box can set weights as
   you on one subnet, and cannot move, unstake or spend anything.

2. Check the settings, especially the measurement, against TESTNET.md:

     gcloud compute ssh $NAME --project=$PROJECT --zone=$ZONE
     sudo \$EDITOR /etc/sentinel/validator.env

3. Stop any validator already running on this hotkey elsewhere, including the
   one on your laptop. weights_rate_limit is 100 blocks, so two of them means
   the second submission is rejected and you debug a rate limit that is working
   exactly as designed.

4. Start it:

     sudo systemctl enable --now sentinel-validator
     journalctl -u sentinel-validator -f

Confirm it is actually scoring, from anywhere:

     btcli subnets metagraph 554 --network test

The validator should read active within a round or two. If it still reads
inactive after half an hour, it is not setting weights, and the journal will
say why: most often no validator permit, or the wrong chain.
EOF
