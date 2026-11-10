# Release v5 on Intel TDX, 10 Nov 2026

Image `sentinel-miner-v5`, UKI 33794b1755d3a108178f8c2b14296200fb965be12dcdaa81cdd62134ac43a2fe2ce8fd9db02bb91ebe96254248b62aec,
built from commit 12c891a and booted under Secure Boot on a Google Cloud c3-standard-4 TDX machine.
Test key server fingerprint fde75d2abdafb50867308b6cb683a908ae778048a501e576143095447bf69edb.

What v5 changes, both shown in these answers:

- The chip signs the TLS key name. `attestation.report_data` equals
  `bind_response(request_id, response_hash, broker, tls)`, not the form without `tls`.
- Every proof carries the boot log (`event_log`), so an answer can be checked on its own.

Files, each with the nonce the client sent:

- `ledger-answer.json`: a Postgres scope query through a read-only view.
- `api-key-answer.json`: an API key scope request to httpbin.org.
- `api-key-headers-answer.json`: the agent tried to set its own Authorization header;
  the enclave added the key last and the echoed header came back `[redacted]`.
- `key-server-tls-ca.crt`: the test key server's CA, which issued the miner's TLS certificate.

Also on this run: a query on the raw table, an off-list path, an off-list method and a `..`
path were refused; `check_miner.py` passed on both scopes without `--accept-unsigned-tls`.
Check any of these answers with `web/verify` or `scripts/check_miner.py`.
The test machines were deleted afterwards.
