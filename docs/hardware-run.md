# Running Sentinel on real SEV-SNP hardware

A confidential VM is metered, so the aim is to arrive knowing exactly what to
type. Capture first, verify second: the bytes are the thing worth paying for,
and anything that goes wrong afterwards is free to debug on a laptop.

Budget a few dollars and under an hour.

---

## 1. Get a confidential VM

Verify current SKU names before booting — confidential-compute offerings move
quickly.

**Azure** (best-trodden path for `/dev/sev-guest`)
- Size: `DCadsv5` or `DCasv5` family
- Image: Ubuntu 22.04/24.04 **confidential** image
- Security type: **Confidential virtual machines**
- Confirm **AMD SEV-SNP**, not Intel TDX

**GCP**
- Machine: `c3d-standard` (Genoa) or `n2d-standard` (Milan)
- Enable **Confidential VM**, and pick **SEV-SNP** rather than plain SEV

Confidential SKUs sometimes need a quota request. Start that before you need it.

---

## 2. Capture a report

```bash
# on the VM — no clone, no pip, stdlib only
curl -sO https://raw.githubusercontent.com/Ayoshiss/sentinel-subnet/main/scripts/capture_report.py
sudo python3 capture_report.py
```

It confirms the device, requests a report, **writes the raw bytes to disk
immediately**, prints the genuine launch measurement, then fetches this chip's
VCEK from AMD and verifies the chain and signature.

If verification fails, that is fine. The report is already saved and the parsing
can be fixed at leisure.

```bash
# from your laptop
scp <user>@<vm>:~/sevsnp-report-*.bin  .
scp <user>@<vm>:~/vcek-*.der           .
scp <user>@<vm>:~/capture-summary.json .
```

**Copy those off before shutting the VM down.** A saved report is a permanent
test fixture; re-renting to get another one is the only unrecoverable mistake
available here.

---

## 3. Pin the real measurement

`capture-summary.json` carries the actual launch measurement — the hash of the
image that really booted. Everything in the repo currently uses a placeholder
(`sha384(b"sentinel-miner-image-v0.1")`), which is symbolic.

Replace it with the captured value in the miner's `SevSnpPolicy`. From that point
"approved code" means a specific image on specific silicon, rather than a string
we chose.

---

## 4. Add the report as a fixture

Drop the blob into `tests/fixtures/` and the existing suite runs against genuine
hardware output with no changes. That is the moment the parser stops being
"correct according to our reading of the spec" and becomes "correct according to
an AMD processor".

---

## If something fails

**`/dev/sev-guest` missing** — the VM is not SEV-SNP, or the guest driver is not
loaded. `lsmod | grep sev`, `dmesg | grep -i snp`. Most often the instance was
created without confidential computing actually enabled.

**Permission denied** — run under `sudo`.

**Firmware returns a non-zero status** — usually an unsupported VMPL or a
malformed request. The status code is in the AMD ABI spec.

**VCEK fetch fails** — KDS is rate-limited and occasionally slow. The chip ID and
TCB in the summary are all that is needed to retry later from anywhere.

**Report signature does not verify** — the interesting failure. It means our
reading of the layout differs from the hardware. The report is saved, so this is
a laptop problem now: compare against `sentinel/sevsnp/report.py`, adjust, and
re-run the tests against the fixture. No further VM time required.

---

## What this changes

Attestation stops being mock-first. The claim moves from

> the protocol is implemented and tested against AMD's certificate chain

to

> reports are produced by an AMD processor and verified against AMD's root

which is the difference between a well-engineered simulation and a working
confidential-compute system.
