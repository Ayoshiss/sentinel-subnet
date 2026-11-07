# Key custody

Which keys decide what a Sentinel miner is allowed to be, who holds them, and
what happens if one is lost or stolen.

## The keys

| Key | What it decides | Held by | Where |
|---|---|---|---|
| **Registry publisher** (subnet owner hotkey) | Which image digests, TD firmware and Secure Boot certificates validators approve | Subnet owner | Bittensor wallet, coldkey password-protected |
| **Secure Boot db key** | What the image's firmware will boot | Subnet owner | Signing laptop, passphrase-encrypted (`image/keys.sh`), offline backup |
| **Secure Boot PK and KEK** | Who may change the db list | Subnet owner | Same as db key. Not needed for routine releases |
| **Key server identity** (`--identity-key`) | Which key server a miner's answers name | Each customer | The customer's key server, mode 0600 |
| **Enclave key** | Who can open a sealed credential | The running enclave | Memory only, never written, new on every boot |

Certificates (the public halves of the Secure Boot keys) are in
`image/secureboot/` and in the registry, because validators and key servers
need them to check a boot.

## The registry is the real authority, not the db key

A validator accepts a TDX miner only if all of these hold:

1. The quote is signed by genuine Intel hardware.
2. The TD firmware (MRTD) is approved in the registry.
3. The only image the firmware loaded has an approved digest in the registry.
4. That image was loaded under Secure Boot with an approved db certificate.

So a stolen db key on its own lets someone boot an image of their choosing,
but that image's digest is not in the registry, so it fails check 3. The db
key matters for check 4, which stops the firmware loading anything else
alongside the approved image. A stolen db key **and** control of the registry
would be needed to pass a modified image. The registry publisher key is
therefore the one to protect most carefully.

A customer's key server applies the same checks with values it chooses itself
(`run_broker.py --measurement --tdx-mrtd --tdx-db-cert`). A customer who pins
those values does not depend on the registry at all.

## How a release is signed

`image/release.sh`:

1. The build VM builds the unsigned image from a pushed commit. It never holds a
   private key.
2. The signing laptop downloads the unsigned UKI and signs it with the db key.
   The passphrase is typed by the person signing.
3. The script checks the signature did not change the approved digest, then
   sends only the signed file back.
4. The GCP image is created with the certificates from `image/secureboot/`.

Anyone can rebuild the same commit and get the same digest without any key,
since the signature sits outside what the digest covers.

## Loss and compromise

- **db key lost.** Running miners are unaffected. No new image can be signed
  under that certificate. Generate new keys, publish a registry that approves the
  new certificate, release under it.
- **db key stolen.** Publish a registry that removes the old certificate (or
  rotate as below), and re-release under a new one. Until then an attacker
  still needs an approved digest, so the exposure is limited (see above).
- **Registry publisher key stolen.** The serious case: an attacker could approve
  their own image. Validators would follow it. Mitigation today is the
  coldkey password; customers who pin their own values in the key server are
  not affected.
- **Key server identity lost.** The customer generates a new one and checks
  for the new fingerprint. Miners re-fetch the credential on restart.

## Rotation

The registry's `tdx.secure_boot_db` is a list, and validators accept a boot
under any certificate in it. To rotate: publish a registry with old and new
certificates, release under the new one, move miners across, then publish a
registry without the old one.

## Not done yet

- One person holds the release keys. There is no second signer and no
  hardware security module.
- The registry is published by a single hotkey. Multi-party approval is
  future work, and part of what an external audit should look at.
