# Run a Sentinel miner

About 30 minutes. You don't install anything on the miner: you boot our signed
image on an Intel TDX machine and configure it from outside.

Read the next two sections before paying for anything.

---

## What you are signing up for

**Netuid 554 is on Bittensor testnet. There are no emissions.** Nothing here
earns. The reason to run one is to test the design and tell us what breaks.
Testnet miners can be subsidised; get in touch before paying for one yourself.

**A Sentinel miner needs an Intel TDX machine.** The validator checks a quote
signed by the processor, so spare capacity of any other kind scores zero. These
instructions use a Google Cloud `c3-standard-4` with TDX, about $168 a month on
demand from Google's list prices on 2026-11-06. AMD SEV-SNP is no longer
accepted: its measurement covers the firmware and nothing above it.

**You run our image, unchanged.** The miner has no shell, no SSH and no guest
agent. The validator reads the TDX boot log and accepts the machine only if it
booted a release on the published list, signed with our key, under Secure Boot.
A changed image fails attestation and scores zero. That is the point: the
customer whose credential reaches your machine needs to know what code holds it.

**What you control** is the configuration the image reads at boot: your hotkey,
who may call you, and the approved values it checks itself against. All of it
is public.

---

## How it works

- The image is a single signed boot file (kernel, initrd and command line) and
  a read-only root filesystem whose hash is on that command line. TDX measures
  the boot file into registers the processor signs.
- At boot the miner reads its configuration from instance metadata, gets a
  quote from the processor and releases the test database credential to
  itself.
- Every answer carries the quote and the boot log, bound to the validator's
  fresh nonce. The validator checks Intel's signature, that debug mode is off,
  the TD firmware, the boot log against the published list, and the answer.
- The published list lives in `measurements.json`. Its hash is on chain, and a
  change takes effect 720 blocks (about 2.4 hours) after it is published.

On the subnet the miner holds the test database's credential itself. That is
fine for testnet data and not for a customer's: a customer runs their own key
server, see `docs/pilot-install.md`.

---

## Prerequisites

- A Google Cloud project with billing enabled, and `gcloud` logged in to it.
  TDX `c3` machines are in a limited set of zones; these steps use
  `us-central1-a`.
- **Access to the image.** Send us the Google account you use with `gcloud`.
  We share the current release with it and reply with the image project.
- Python 3.11+ locally.
- A Bittensor wallet with a little testnet TAO. Registration burn is about
  τ0.0005, so a faucet drip is plenty.

---

## 1. Get the code

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet.git
cd sentinel-subnet
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

You need it on your laptop for the approved values, the checker and publishing
your endpoint. Nothing from it is copied to the miner.

## 2. Create a hotkey and register it on 554

```bash
.venv/bin/btcli wallet new-hotkey --wallet <your-wallet> --wallet-hotkey sentinel-miner
```

```bash
.venv/bin/btcli subnet register --netuid 554 --network test --wallet <your-wallet> --hotkey sentinel-miner
```

Note the ss58 address it prints.

**No wallet key goes on the miner.** It never signs with the hotkey: it checks
its callers' signatures, and its answers are signed by the processor.

## 3. Reserve an address and open the port

```bash
gcloud compute addresses create sentinel-miner --region us-central1
gcloud compute firewall-rules create sentinel-miner --allow tcp:8091 --target-tags sentinel-miner
```

The rule opens the port to everyone; the miner itself refuses callers not on
its list (step 4).

## 4. Write the configuration

The miner refuses anyone not on `allow_hotkey`. Put the subnet's validators
there (uid 0 is in `TESTNET.md`; check the metagraph for others with a validator
permit), plus the checker address from step 6.

```bash
.venv/bin/python - <<'EOF'
import base64, json
reg = json.load(open("measurements.json"))
release = next(m for m in reg["measurements"] if m["platform"] == "gcp-tdx")
config = {
    "hotkey_ss58": "<your ss58 from step 2>",
    "measurement": release["measurement"],
    "tdx_mrtd": reg["tdx"]["mrtd"],
    "tdx_db_cert_b64": base64.b64encode(open("image/secureboot/db.der", "rb").read()).decode(),
    "allow_hotkey": ["5H5uDA7TRyisfPLgRJaFYhVZEQ7mhKPb2mZJVwSw6UvKo3RV"],
    "no_allow_validators": True,
}
json.dump(config, open("miner-config.json", "w"), indent=1)
print("release", release["image"])
EOF
```

The release it prints is the image you boot in step 5. The miner checks its own
measurement against this file and refuses to serve if they differ.

`no_allow_validators` is needed because the image has no chain access to read
the validator list itself, so the list is the one you write.

## 5. Boot the miner

```bash
gcloud compute instances create sentinel-miner --zone us-central1-a \
  --machine-type c3-standard-4 --confidential-compute-type TDX \
  --shielded-secure-boot --maintenance-policy TERMINATE \
  --image <release from step 4> --image-project <the image project we sent you> \
  --address sentinel-miner --tags sentinel-miner \
  --no-service-account --no-scopes \
  --metadata-from-file sentinel-miner=miner-config.json
```

TDX machines cannot live migrate, so the maintenance policy is TERMINATE and
the machine restarts after host maintenance on its own.

There is no shell, so the serial console is the only view in:

```bash
gcloud compute instances get-serial-port-output sentinel-miner --zone us-central1-a | grep sentinel.miner
```

Within a minute you should see, in order:

- `Intel TDX guest detected`
- a warning that the miner releases credentials to itself (expected on the subnet)
- `credential released to the enclave for 'customer-db', sealed, by broker <fingerprint>`
- `miner serving https on 0.0.0.0:8091`

Note the broker fingerprint. It is new on every boot.

## 6. Check it yourself

`check_miner.py` runs the validator's checks from your laptop against the
published list.

```bash
.venv/bin/python scripts/check_miner.py --url https://<your address>:8091 \
  --miner-hotkey <your ss58> --expected-broker <fingerprint from step 5>
```

The first run creates a local checking key and is refused, because that key is
not on your list. Add the address it names to `allow_hotkey` in
`miner-config.json`, then apply it and restart:

```bash
gcloud compute instances add-metadata sentinel-miner --zone us-central1-a --metadata-from-file sentinel-miner=miner-config.json
```

```bash
gcloud compute instances reset sentinel-miner --zone us-central1-a
```

Read the new fingerprint from the serial log and run the check again. You want
`"verified": true` with attestation and correctness both 1.0.

## 7. Publish the endpoint

From your laptop, where the wallet lives:

```bash
.venv/bin/python scripts/publish_axon.py --netuid 554 --network test \
  --wallet <your-wallet> --hotkey sentinel-miner --ip <your address> --port 8091
```

ServeAxon is rate limited, roughly once per 50 blocks, so do this at setup and
on address changes only.

## 8. Confirm the validator scores you

```bash
.venv/bin/btcli subnets metagraph 554 --network test
```

A round runs about every 22 minutes. After one or two, your uid should carry
weight. If it doesn't, tell us your uid and we'll read the validator's log.

---

## Moving to a new release

Releases are announced before they take effect: a new list is published on
chain and applies 720 blocks later. To move, write the configuration again
(step 4), then delete the machine and boot it from the new image (step 5). The
address, hotkey and registration stay the same.

```bash
gcloud compute instances delete sentinel-miner --zone us-central1-a
```

The old release stays accepted until a list without it takes effect, so there
is time to move.

---

## When it goes wrong

**`sentinel-miner metadata refused`.** A key in `miner-config.json` is unknown,
has the wrong type, or a value starts with `-`. The message names it.

**`launch measurement mismatch`.** The image you booted is not the one in your
configuration. Boot the release step 4 printed.

**`Security Violation` in the serial log, nothing after.** Secure Boot refused
the boot file. The machine was created without `--shielded-secure-boot`, or from
an image that is not ours.

**`HTTP 401 ... is not permitted`.** The caller is not on `allow_hotkey`. For
the validator, check its hotkey against the metagraph.

**`answered from broker ..., not ours`** from `check_miner`. The fingerprint is
from an earlier boot. Read the current one from the serial log.

**Nothing discovers you.** Almost always the wrong network. 554 is testnet, so
every command needs `--network test`.

---

## Honest limits

- **We hold the signing key.** The published list means "images we signed".
  The builds are reproducible: `image/release.sh build` on the release commit
  gives the same measurement. Rebuilding one and telling us whether it matched
  is the most useful check you can do.
- **The subnet's test credential is held by the miner itself.** That proves
  the mechanism, not custody. Custody is the key server on the customer's side.
- **Payments and slashing are not built.**

## Feedback worth sending

Criticism is more useful than approval:

- Where did this break, and how long did it take end to end?
- Would you run a paid TDX machine for a subnet, and at what emission level?
- Is booting an image you can't log in to acceptable to you as an operator?
- What would stop you running one?
