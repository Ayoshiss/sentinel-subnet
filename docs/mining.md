# Run a Sentinel miner

About an hour, most of it waiting for a VM to install packages.

Read the next two sections before provisioning anything. They cover what is
different here from other subnets, and what is not finished.

---

## What you are signing up for

**Netuid 554 is on Bittensor testnet. There are no emissions.** Nothing here
earns. The reason to run one is to evaluate the design and report what breaks.

**A Sentinel miner needs a confidential VM, not spare capacity.** Most subnets
let you point hardware you already own at the problem. This one cannot: the
whole design rests on an AMD SEV-SNP processor proving which code is running
before a credential is released to it. That means a specific machine type, and
it costs roughly $30 a month on GCP spot pricing. Testnet miners can be
subsidised; get in touch before paying for one yourself.

**Every miner must run a byte-identical image.** The validator pins one approved
launch measurement. A different image measures differently and scores zero. This
is an operational burden and an open design question.

---

## Known limitation: the measurement does not cover application code

The SEV-SNP launch measurement covers the boot state of the VM, not the Python
application on top of it. Tested on a live miner: modifying the miner's code and
the data it served left the measurement byte-identical, and the validator still
scored the attestation 1.0. The chip proves what *booted*, not what is *running*.

Closing this means binding the root filesystem into the measurement. Until then,
treat this as an incentive mechanism and a deployment path rather than a
finished security guarantee.

---

## Prerequisites

- A GCP project with billing enabled, and `gcloud` logged in to it.
- Python 3.11+ locally.
- A Bittensor wallet with a little testnet TAO. Registration burn is about
  τ0.0005, so a faucet drip is plenty.

Confidential VMs are available in most regions. These instructions use
`us-central1-a`.

---

## 1. Get the code

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet.git
cd sentinel-subnet
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 2. Create a hotkey and register it on 554

The hotkey is the miner's identity. It never needs your coldkey on the server.

```bash
.venv/bin/btcli wallet new-hotkey --wallet <your-wallet> --wallet-hotkey sentinel-miner
```

```bash
.venv/bin/btcli subnet register --netuid 554 --network test --wallet <your-wallet> --hotkey sentinel-miner
```

Note the ss58 address it prints. You need it twice below.

## 3. Provision the confidential VM

```bash
PROJECT=<your-gcp-project> ZONE=us-central1-a NAME=sentinel-miner-1 ./deploy/provision-gcp.sh
```

This creates an `n2d-standard-2` with SEV-SNP enabled, opens tcp:8091 to
validators, and installs the miner without starting it. It prints the external
IP. Keep it.

Confidential instances cannot live migrate, so the maintenance policy is
TERMINATE and the instance is set to restart on failure. Expect it to bounce
occasionally. That is normal and the miner comes back on its own.

Confirm the hardware is genuinely what it claims before trusting any of it:

```bash
gcloud compute ssh sentinel-miner-1 --zone=us-central1-a --command 'ls -l /dev/sev-guest && sudo dmesg | grep -i sev-snp'
```

You want to see `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`.

## 4. Read the launch measurement

The image has to tell you what it measures as; you cannot decide it.

```bash
gcloud compute ssh sentinel-miner-1 --zone=us-central1-a --command \
  'cd /opt/sentinel && sudo .venv/bin/python scripts/run_miner.py --print-measurement'
```

If this does not match the measurement the validator has pinned, the miner will
serve normally and score zero. Compare it against the value in TESTNET.md, and
report a mismatch: image drift across miners is an open coordination problem.

## 5. Configure and start

```bash
gcloud compute ssh sentinel-miner-1 --zone=us-central1-a
sudo tee /etc/sentinel/miner.env <<EOF
HOTKEY_SS58=<the ss58 from step 2>
MEASUREMENT=<the measurement from step 4>
EOF
sudo systemctl enable --now sentinel-miner
journalctl -u sentinel-miner -f
```

You should see the chip detected, then a credential released to the enclave,
then the miner serving on 0.0.0.0:8091.

**No wallet key goes on this machine.** The miner serves under an address it
holds no private key for. It never signs with the hotkey: it verifies its
callers' signatures, and its own answers are signed by the chip. If the VM is
compromised, the attacker gets a miner that answers queries, not your identity.

### Who is allowed to call you

Checking a signature proves a caller holds a hotkey. It says nothing about
whether they should be querying your enclave, and the query tool takes SQL, so
an unrestricted miner lets any hotkey on the network run reads against whatever
database it is attached to.

So the miner keeps an allowlist. By default that is the validators holding a
permit on the subnet, read from chain at startup and refreshed every ten
minutes. If the chain cannot be reached the previous list stands, because a
miner that goes dark during an RPC outage scores zero for something that is not
its fault.

```bash
--allow-hotkey 5Fdv...ddf    # permit a specific caller, repeatable
--no-allow-validators        # use only the hotkeys named above
--allow-any                  # permit anyone: demos only, never real data
```

With no list and no reachable chain the miner refuses to start rather than
serving everyone. Opening it up has to be something you typed.

### Keeping it alive

A SEV-SNP guest can lose attestation permanently while the process keeps
running: a timed-out request to the AMD security processor makes the kernel
disable the VMPCK, and only a reboot brings it back. `/health` returns 503 once
that has happened rather than reporting healthy from cached identity.

```bash
sudo cp deploy/sentinel-watchdog.service /etc/systemd/system/
sudo systemctl enable --now sentinel-watchdog
```

It reboots after three consecutive 503s and stops after two reboots in an hour,
because a host whose security processor is failing will fail again and a boot
loop hides that. See SECURITY.md for the full detail.

### Scoping what a caller can read

Attestation decides which code runs. The allowlist decides who may call. The
read-only role decides whether they may write. None of those limit *what* can be
read, so by default a caller reaches everything the credential reaches.

Scopes fix that. Each is its own restricted credential, unlocked by its own
attestation, and exposed as its own tool named `<scope>.query`:

```bash
--scope analytics=postgresql://sentinel_analytics:...@host/db \
--scope support=postgresql://sentinel_support:...@host/db
```

An API key can then be limited to a subset. In the key file:

```json
{ "support-bot": { "digest": "...", "scopes": ["support"] } }
```

That key sees only `support.query` in `/tools` and is refused `analytics.query`.
A key with a bare digest reaches every scope, which is the right default when
there is only one database.

`docs/scoping.sql` is a worked example of the views and roles a DBA creates. The
important part is there rather than here: the enclave can only be as restricted
as the credential it is given.

### Running the broker on the customer's machine

By default the miner builds the broker in its own process, which means it holds
the database password and releases it to itself. The verification runs and proves
nothing about custody: a customer reading the code can reasonably point out that
the secret is the operator's own variable. That default is fine for the subnet,
where the database is seeded test data, and wrong for anybody's real database.

To separate them, the customer runs the broker and keeps the DSN there:

```bash
python scripts/run_broker.py   --scope analytics="postgresql://sentinel_analytics:...@db/app"   --measurement <approved hex>   --bind 0.0.0.0 --port 8100
```

The miner then asks for the scope by name and holds no secret of its own:

```bash
python scripts/run_miner.py --scope analytics   --measurement <approved hex>   --broker-url https://broker.customer.example:8100
```

Notice `--scope` takes a bare name here. Passing `NAME=DSN` with `--broker-url`
is refused, because a DSN on this host is exactly what the split exists to
prevent.

Verification happens on the customer's side, using certificates the enclave
sends with its report. That sounds like asking the accused to supply the
evidence, and it would be, except AMD's root is pinned on the broker: a chain
generated by the miner fails there. What it buys is verification that keeps
working when AMD's KDS is unreachable.

Use `https`: the released credential travels in that response body, and
`--broker-insecure` exists only so the pair can be rehearsed over loopback.
Terminate TLS on the broker's own machine rather than behind a proxy you do not
control.

Now the part a customer deserves to hear from you rather than discover. TLS here
does not protect the credential from **you**, the operator of the miner's host.
The client does not pin the broker's certificate, so it validates against the
guest's system trust store, and you own that store. Since the launch measurement
does not cover the root filesystem, you could add a certificate authority, proxy
the broker and read the DSN without the measurement changing.

What the split genuinely gives a customer is therefore narrower than
"unobtainable": taking their credential stops being something you could do by
reading a variable and becomes active interception of your own guest, which is
deliberate, and which they can hold you to. Say it that way. Overselling it is
how an operator loses a customer permanently, and the repository documents the
hole either way, in `docs/threat-register.md` under T22 and T23.

To rehearse both ends on one machine, give the mock chip a fixed identity so the
broker can trust it in advance:

```bash
python scripts/run_miner.py --allow-mock --mock-chip-seed $(openssl rand -hex 32) ...
```

The miner logs the `--allow-mock-chip CHIPID=PUBKEY` line to paste into the
broker. Real silicon needs none of this, because AMD's chain identifies the chip.

### Callers who are not on Bittensor

Validators authenticate with a hotkey signature. A customer running Sentinel
over their own database has no hotkey, so for that deployment the miner also
accepts API keys.

```bash
python scripts/make_api_key.py --label analytics-agent \
  --keys /etc/sentinel/api-keys.json
```

The key is printed once and never stored. The file holds SHA-256 digests, so
leaking it hands over nothing, and losing a key means minting another and
removing the old label. Start the miner with `--api-keys /etc/sentinel/api-keys.json`
and the caller sends `Authorization: Bearer <key>`.

One difference worth understanding before choosing it. A signed request carries
a nonce and a timestamp, so it cannot be replayed. A bearer token has no such
property: anyone who captures a request can repeat it. Over TLS against
read-only tools that is usually acceptable, but it is not equivalent, and on the
subnet you should keep hotkey authentication.

## 6. Publish the endpoint

From your laptop, where the wallet actually lives:

```bash
.venv/bin/python scripts/publish_axon.py --netuid 554 --network test \
  --wallet <your-wallet> --hotkey sentinel-miner --ip <the external IP> --port 8091
```

ServeAxon is rate limited per neuron, roughly 50 blocks, so this belongs at
setup and on address changes, not in a loop.

## 7. Check you are discoverable

```bash
.venv/bin/btcli subnets metagraph 554 --network test
```

And that the miner answers from outside:

```bash
curl http://<the external IP>:8091/health
```

That returns the chip id, the launch measurement, and AMD's certificate chain.
Handing out the certificates is deliberate: they are public, and the chain is
checked against a root pinned in the verifier, so verification never has to
reach AMD's key service.

---

## When it goes wrong

**Miner exits with "launch measurement mismatch".** The image is not the one
pinned, which is the gate working as intended. Read the running value and report
it.

**`no /dev/sev-guest`.** The VM was not created as confidential. Check the
instance was made with `--confidential-compute-type=SEV_SNP`.

**Scores zero on correctness with a valid attestation.** The database is not
seeded, so the validator's probe hits a missing table. `scripts/miner-seed.sql`
is applied automatically on a fresh SQLite database.

**Nothing discovers you.** Almost always the wrong network. 554 is testnet, so
every command needs `--network test`. Publishing to finney succeeds against the
wrong chain and leaves you invisible with no error anywhere.

---

## Feedback worth sending

Criticism is more useful than approval. Specifically:

- Where did this break, and how long did it take end to end?
- Would you run a paid confidential VM for a subnet, and at what emission level?
- Is the single-pinned-image requirement manageable or a dealbreaker?
- What would stop you running one?
