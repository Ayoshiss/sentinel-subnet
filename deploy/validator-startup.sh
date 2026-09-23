#!/usr/bin/env bash
#
# GCP startup script for a validator. Runs as root on first boot.
#
# Installs the validator and leaves it stopped, because starting it needs a
# wallet hotkey and a hotkey should never be baked into an image.
#
# Nothing here checks for SEV-SNP, and that is the point: a validator verifies
# attestations rather than producing them, so it needs no confidential hardware
# and no special machine type. That is what makes validating the cheap side of
# this subnet and worth saying out loud to anyone deciding whether to run one.

set -euo pipefail

exec > >(tee /var/log/sentinel-startup.log) 2>&1
echo "sentinel validator startup $(date -Is)"

apt-get update -qq
apt-get install -y -qq python3-venv python3-dev git build-essential pkg-config

# An e2-micro has 1GB of RAM and the dependency tree builds native wheels. With
# no swap, pip is killed by the OOM reaper partway through and leaves a venv
# that looks installed and imports nothing. 2GB of swap costs a little disk and
# removes an hour of confusing debugging.
if [ ! -e /swapfile ]; then
    echo "creating swap, 1GB of RAM is not enough to build the dependencies"
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

id -u sentinel >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin sentinel

git clone --depth 1 https://github.com/Ayoshiss/sentinel-subnet.git /opt/sentinel
cd /opt/sentinel
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

install -d -m 0750 -o sentinel -g sentinel /etc/sentinel
install -m 0640 -o root -g sentinel \
    /opt/sentinel/deploy/validator.env.example /etc/sentinel/validator.env

# The wallet directory has to exist and be owned by the service user before the
# hotkey is copied in, or the copy lands as root and the service cannot read it.
install -d -m 0700 -o sentinel -g sentinel /home/sentinel/.bittensor/wallets

chown -R sentinel:sentinel /opt/sentinel
install -m 0644 /opt/sentinel/deploy/sentinel-validator.service /etc/systemd/system/
systemctl daemon-reload

echo "installed and stopped. The hotkey still has to be copied in by hand."
