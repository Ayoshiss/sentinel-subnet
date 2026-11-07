# Pilot install

How a pilot customer connects their database and their agent to Sentinel. Plan
on about an hour, most of it in step 1.

```
your network                              Sentinel machine (Intel TDX)
------------                              ----------------------------
PostgreSQL  <--- queries ---------------  measured image
key server  --- sealed password ------->    opens it inside the enclave
                                            answers your agent over MCP
your agent  --- MCP + API key --------->    every answer signed
```

**You run** the key server, next to your database. It holds the password.
**We run** the Sentinel machine on Google Cloud, or you run it in your own
Google Cloud project with the same image.

## 1. Create a restricted database role

Sentinel never needs a role that can read everything. Create one that can only
`SELECT` from the views the agent should see. `docs/scoping.sql` is a worked
example: one view per scope, one login role per scope, no table grants, and
`public` schema access revoked.

Data outside those views is unreachable, not just unrequested. Sentinel also
refuses write statements by default, but the role is the boundary that matters.

## 2. Install the key server

Any small Linux machine that can reach the database and that the Sentinel
machine can reach on one port. Use the same release the image was built from.

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet.git && cd sentinel-subnet
git checkout <release commit>
python3 -m venv .venv
.venv/bin/pip install --require-hashes --only-binary=:all: -r image/requirements.lock
```

## 3. Start it

The approved values are in `measurements.json`: the image digest
(`measurements[].measurement`), the TD firmware (`tdx.mrtd`), and the Secure
Boot certificate (`image/secureboot/db.der`). Checking them yourself, rather than
trusting ours, is the point: you can rebuild the image from the release commit
with `image/build.sh` and compare the digest.

```bash
.venv/bin/python scripts/run_broker.py \
  --scope analytics='postgresql://sentinel_analytics:<password>@db.internal/prod' \
  --measurement <image digest> \
  --tdx-mrtd <mrtd> \
  --tdx-db-cert image/secureboot/db.der \
  --identity-key /etc/sentinel/key-server.pem \
  --bind 0.0.0.0 --port 8100
```

On first start it creates `--identity-key` and logs its **fingerprint**. Write
the fingerprint down: every answer Sentinel gives will name it, and it is how
you tell your setup apart from anyone else's. Back the key file up; a new key
means a new fingerprint.

Firewall port 8100 so only the Sentinel machine can reach it. The password is
sealed to the enclave before it leaves, so it is unreadable on the wire either
way, but there is no reason to expose the port.

## 4. Make an API key for your agent

```bash
.venv/bin/python scripts/make_api_key.py --label pilot-agent
```

It prints the key once. Give your agent the key. Give us only the digest it
prints, which is what the Sentinel machine checks against; a digest is useless
to anyone who reads it.

## 5. Connect the agent

Sentinel speaks MCP over Streamable HTTP:

- **URL:** `http://<sentinel host>:8091/mcp` (plain HTTP today, see the end of this page)
- **Header:** `Authorization: Bearer <API key>`

Any MCP client that supports remote servers with a custom header can connect.
`tools/list` shows one query tool per scope. Every `tools/call` result carries
the rows as text, and the proof in `structuredContent`: the hardware
attestation, the hash of the answer, and the fingerprint of the key server the
password came from. To make the proof fresh rather than just genuine, send your
own random value as `params._meta.nonce`.

## 6. Check it is your setup

```bash
.venv/bin/python scripts/check_miner.py \
  --url http://<sentinel host>:8091 --miner-hotkey <from /health> \
  --expected-broker <your fingerprint>
```

The first run prints a local address to add to the miner's allow list. After
that, exit status 0 means: genuine Intel TDX, the approved image and firmware,
Secure Boot under the approved certificate, and answers that name your key
server. Run it whenever you like; a scheduled run is a cheap monitor.

## Changing the password

Change it in the database and in the key server's `--scope`, restart the key
server, and ask us to restart the Sentinel service. The enclave fetches the new
password on start; the old one is only ever in memory.

## What this does not do

- **The agent's connection is not encrypted yet.** The password is sealed to
  the enclave, but the API key and the query results travel between your agent
  and the Sentinel machine over plain HTTP. Whoever can see that network path
  can read them, and if we run the machine, that includes us. Until TLS ends
  inside the enclave, run the Sentinel machine in your own Google Cloud
  project, on a private network your agent reaches directly.
- Query results go to your agent, and from there to whichever AI model it
  uses. Sentinel controls what the agent can reach, not where it sends it.
- PostgreSQL only, SQL only.
- Intel TDX on Google Cloud only. Google's firmware is part of the chain of
  trust.
- Not yet independently audited.
- If the Sentinel machine is pointed at a key server that isn't yours, it
  still works, but the answers name that key server and step 6 fails. Run the
  check; that is what it is for.
