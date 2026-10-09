# Part I — Operations Guide

How to install, run and test the C-ITS-PKI utility and its scripts. For how it works
and why, see [Part II — Implementation](implementation.md). For standards evidence, see
[Part III — Compliance](compliance.md). References [Rn] are listed in the
[appendix](references.md).

- [1. Installation](#1-installation)
- [2. Choosing a format: v2 or v3](#2-choosing-a-format-v2-or-v3)
- [3. PKI directory layout](#3-pki-directory-layout)
- [4. CLI reference](#4-cli-reference)
- [5. Workflows](#5-workflows)
- [6. Scripts](#6-scripts)
- [7. Test suites](#7-test-suites)
- [8. Using the output with Vanetza-NAP](#8-using-the-output-with-vanetza-nap)
- [9. Troubleshooting](#9-troubleshooting)

---

## 1. Installation

| Requirement | Version | Notes |
|---|---|---|
| Python | ≥ 3.13 | declared in `pyproject.toml` |
| [uv](https://docs.astral.sh/uv/) | any recent | used by all scripts (`uv run python`) |
| `cryptography` [R28] | ≥ 46.0.5 | ECDSA, ECDH, AES-CCM/ECB, key files |
| `asn1tools` [R27] | ≥ 0.167.0 | COER codec for v3 structures |
| `tinyec` [R29] | ≥ 0.4.0 | EC point addition for butterfly keys |

```bash
cd C-ITS-PKI
uv sync                      # creates .venv from pyproject.toml / uv.lock
uv run python cli.py --help
```

Without uv: `pip install -r requirements.txt`, then run `python3 cli.py …`. The test
suites (section 7) are separate uv projects under `tests/v2` and `tests/v3`, and
`run_all.sh` syncs them automatically.

## 2. Choosing a format: v2 or v3

The format is fixed when a PKI is created (`init --etsi-version`) and recorded in
`pki_meta.json`. Later commands detect it automatically (section 4.1).

| | **v2** (default) | **v3** |
|---|---|---|
| Standard | ETSI TS 103 097 V1.2.1 [R4] | ETSI TS 103 097 V1.3.1 [R3] profile of IEEE 1609.2-2016 [R9]; profiles checked against V2.2.1 [R1] |
| Encoding | TS 103 097 V1.2.1 presentation language (custom binary) | ASN.1 COER, ITU-T X.696 [R12] |
| Certificate version byte | `0x02` | `0x80` preamble, then version `0x03` |
| Signed message | `SecuredMessage`, protocol version 2 | `EtsiTs103097Data`, protocol version 3 |
| Vanetza-NAP mode | `VANETZA_SECURITY=certs-v2` | `VANETZA_SECURITY=certs-v3` |
| Curves | NIST P-256 only | NIST P-256 only (see [DD-02](design-decisions.md#dd-02)) |

Use **v3** for new work; it is the current C-ITS format. Use **v2** for stacks that only
speak TS 103 097 V1.2.1.

## 3. PKI directory layout

`init` creates the hierarchy. The other commands write below it:

```
<pki>/
├── pki_meta.json          {"algorithm": 0, "region_ids": null, "etsi_version": 1|2, "entities": [...]}
├── root_ca.cert           Root CA (self-signed)          root_ca_sign.key
├── tlm.cert               Trust List Manager (self-signed) tlm_sign.key
├── ea.cert                Enrolment Authority            ea_sign.key  ea_enc.key
├── aa.cert                Authorization Authority        aa_sign.key  aa_enc.key
├── its-stations/<name>/   ec.cert  ec_sign.key           (enrol)
├── tickets/               at_<unix-ts>.cert  at_<unix-ts>_sign.key   (issue-at)
└── bke-tickets/           butterfly batch                (butterfly-at, section 4.5)
```

- `etsi_version`: `1` means v2 and `2` means v3. These are internal enum values
  (`EtsiVersion.V1_2_1` / `V2_2_1`); see [DD-01](design-decisions.md#dd-01).
- `*.cert`: raw binary certificates in the selected format.
- `*.key`: **unencrypted** PKCS#8 DER private keys (see [DD-16](design-decisions.md#dd-16)).
  Both Vanetza-NAP loaders accept this format.

## 4. CLI reference

`uv run python cli.py <command> [options]`. Every command also accepts `--help`.

### 4.1 Format auto-detection

`verify-sig`, `encrypt`, `verify-cert` and `info` decode certificates in this order:

1. `--etsi-version v2|v3` if given;
2. otherwise `pki_meta.json` in the certificate's directory or up to 3 parent directories;
3. otherwise `v2`.

`enrol`, `issue-at` and `butterfly-at` read the format from `<pki>/pki_meta.json`.
`sign-*` and `decrypt` detect the format from the certificate and message bytes, and
signed and encrypted messages always follow the certificate's format
([DD-11](design-decisions.md#dd-11)).

### 4.2 `init` — create the PKI hierarchy

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` | `pki-output` | PKI directory |
| `--etsi-version` | `v2` | `v2` or `v3` (section 2) |
| `--algo` | `p256` | only `p256` is accepted ([DD-02](design-decisions.md#dd-02)) |
| `--region` | none | comma-separated identified-region country IDs, e.g. `65535` = EU-27 [R1 cl. 6] |
| `--root-name`, `--tlm-name`, `--ea-name`, `--aa-name` | `C-ITS-Root-CA`, `C-ITS-TLM`, `C-ITS-EA`, `C-ITS-AA` | certificate names |

Issues the Root CA (10 years), TLM (10 years), EA and AA (5 years each), with separate
signing and encryption keys for the EA and AA.

```bash
uv run python cli.py init --output pki-output --etsi-version v3
```

### 4.3 `enrol` — issue an Enrolment Credential

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` | `pki-output` | PKI directory |
| `--name` | required | station name, becomes the EC `id` (name) |
| `--validity` | 1 | validity in years |
| `--ec-output` | `<pki>/its-stations/<name>` | output directory |

Writes `ec.cert` and `ec_sign.key`.

### 4.4 `issue-at` — issue one Authorization Ticket

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` | `pki-output` | PKI directory |
| `--psid` | `36,37` | comma-separated ITS-AIDs [R7] (CAM, DENM) |
| `--validity` | 168 | validity in hours |
| `--at-output` | `<pki>/tickets` | output directory |

Writes `at_<unix-ts>.cert` and `at_<unix-ts>_sign.key`. With v2, every AID must be in
the AA's list (`36, 37, 141, 623`), otherwise the command fails with an explanation
([DD-06](design-decisions.md#dd-06)).

### 4.5 `butterfly-at` — issue a butterfly batch (IEEE 1609.2.1)

| Option | Default | Meaning |
|---|---|---|
| `--output`, `-o` | `pki-output` | PKI directory |
| `--count` | 8 | number of ATs, `j = 0 … count-1` |
| `--mode` | `original` | `original` (separate encryption caterpillar) or `unified` [R5 cl. 6.2.3.5.2] |
| `--i-value` | weeks since 2004-01-01 | i-period used in the expansion ([DD-12](design-decisions.md#dd-12)) |
| `--psid` | `36,37` | ITS-AIDs |
| `--validity` | 168 | validity in hours |
| `--at-output` | `<pki>/bke-tickets` | output directory; old batch files there are deleted |

The command plays the end entity, EA and AA roles locally (see
[implementation §8](implementation.md#8-butterfly-key-mechanism)). It writes:

| File | Content |
|---|---|
| `butterfly.json` | `{"mode", "i_value", "count", "standard"}` |
| `caterpillar_sign.key`, `sign_expansion.key` | caterpillar signing key (PKCS#8 DER) and its 16-byte expansion key |
| `caterpillar_enc.key`, `enc_expansion.key` | original mode only: encryption caterpillar and expansion key |
| `bke_at_<j>.cert` | butterfly AT *j* |
| `bke_at_<j>.offset` | the AA's random offset *r* (32 bytes, big-endian) |
| `bke_at_<j>_sign.key` | reconstructed AT private key `sk_cc + r` (PKCS#8 DER) |

Every reconstructed key is checked against its certificate before it is written.

### 4.6 `sign-cam` / `sign-denm` — sign a message

| Option | Commands | Meaning |
|---|---|---|
| `--at-key`, `--at-cert` | both | AT private key and certificate; the certificate selects v2/v3 |
| `--payload` | both | file with the message payload (opaque bytes) |
| `--output`, `-o` | both | default `<payload>.signed` |
| `--full-cert` | `sign-cam` | signer = full certificate instead of digest |
| `--lat`, `--lon`, `--elev` | `sign-denm` | generation location in decimal degrees / metres |

CAMs follow [R1 cl. 7.1.1] / [R4 cl. 7.1] and DENMs follow [R1 cl. 7.1.2] / [R4 cl. 7.2]
(see [implementation §6](implementation.md#6-signed-messages)).

### 4.7 `verify-sig` — verify a signed message

| Option | Meaning |
|---|---|
| `--signed` | signed message (v2 or v3, detected) |
| `--at-cert` | AT that signed it; required for digest-signed messages |
| `--aa`, `--root` | also verify the certificate chain AT → AA → Root |
| `--etsi-version` | override certificate format detection |

Prints the format, the signature result, PSID, generation time, signer and location,
and the chain checks when `--root` is given. Exit code 0 means `VALID`.

### 4.8 `encrypt` / `decrypt`

| Option | Meaning |
|---|---|
| `--enc-cert` | recipient certificate; must contain an encryption key (EA, AA) |
| `--enc-key` | recipient encryption private key (required but only used by `decrypt`) |
| `--payload` / `--input` | plaintext (encrypt) / encrypted message (decrypt) |
| `--output`, `-o` | default `<payload>.enc` / `<input>.dec` |

`encrypt` produces `EtsiTs103097Data-Encrypted` (v3) or an encrypted `SecuredMessage`
(v2). Encrypting a signed message gives the signed-and-encrypted profile. `decrypt`
returns the inner bytes, e.g. the signed message, which can then be passed to
`verify-sig`.

### 4.9 `verify-cert` — check a certificate

| Option | Meaning |
|---|---|
| `--cert` | certificate to check |
| `--issuer` | issuing certificate (omit for self-signed) |
| `--etsi-version` | override detection |

Checks the signature, validity period, cracaId/crlSeries (v3), permissions, region,
the AT profile (for `id = none`), and that the issuer digest matches `--issuer`.
Exit code 0 means `VALID`.

### 4.10 `info` — show a certificate

`--cert FILE [--etsi-version v2|v3]`. Prints the decoded fields, the encoded size and
the HashedId8.

## 5. Workflows

### 5.1 Complete v3 flow

```bash
P="uv run python cli.py"
$P init      --output pki --etsi-version v3
$P enrol     --output pki --name ITS-Station-001
$P issue-at  --output pki --psid 36,37 --validity 168
AT=$(ls pki/tickets/at_*.cert); KEY=${AT%.cert}_sign.key
printf 'CAM_PAYLOAD' > cam.bin
$P sign-cam  --at-key $KEY --at-cert $AT --payload cam.bin --output cam.signed
$P verify-sig --signed cam.signed --at-cert $AT --aa pki/aa.cert --root pki/root_ca.cert
$P encrypt   --enc-cert pki/ea.cert --enc-key pki/ea_enc.key --payload cam.signed --output cam.enc
$P decrypt   --enc-cert pki/ea.cert --enc-key pki/ea_enc.key --input cam.enc --output cam.dec
$P verify-sig --signed cam.dec --at-cert $AT
```

### 5.2 Butterfly batch

```bash
$P butterfly-at --output pki --count 20 --mode unified
$P verify-cert  --cert pki/bke-tickets/bke_at_0.cert --issuer pki/aa.cert
$P sign-cam     --at-key pki/bke-tickets/bke_at_0_sign.key \
                --at-cert pki/bke-tickets/bke_at_0.cert --payload cam.bin
```

## 6. Scripts

| Script | Purpose | Notes |
|---|---|---|
| `gen-verify.sh [v2\|v3]` | End-to-end check of all workflows (init, enrol, AT, butterfly batch, CAM/DENM sign and full-chain verify, encrypt, decrypt) for one or both formats | Deletes and recreates `pki-output/`, `cam.*`, `denm.*` in the repo root. Exit code 0 with every `Overall: VALID` is the pass criterion. |
| `gen-vnap-certs.sh [any-arg]` | Generates the Vanetza-NAP simulation certificates and copies them into `$TARGET_DIR` | No argument means v3; **any** argument means v2 (the usage text says otherwise). Output directory is `$VAR` (default `./vnap-certs`). `TARGET_DIR` (environment) is vnap-secure's `certs/c-its-pki`; by default the script finds it from vnap-secure's submodule `external/C-ITS-PKI` or from a checkout next to vnap-secure. It stops (`exit`) after copying, so its EC/message steps are not run. |
| `_clean.sh` | Removes generated files | Deletes `cam.*`, `denm.*`, `*.key` in the repo root, `vnap-certs/`, `src/__pycache__`, and all `.venv` directories. |

`gen-vnap-certs.sh` places these files in the simulation directory: `root_ca.cert`,
`aa.cert`, `ea.cert`, `tlm.cert`, `at.cert` + `at.der` (the regular AT and key), and
`bke_at_<j>.cert` + `bke_at_<j>_sign.der` (butterfly ATs).

## 7. Test suites

Two suites of 9 shell test files each, one per format:

```bash
bash tests/v2/run_all.sh          # v2 format
bash tests/v3/run_all.sh          # v3 format
PYTHON="uv run python" bash tests/v3/test_05_signing.sh   # a single file, from the repo root
```

| File | Covers |
|---|---|
| `test_01_keygen.sh` | key generation, compressed points, CSPRNG distinctness |
| `test_02_root_ca.sh` | Root CA profile, encoding round trip, P-384 rejection (v3) |
| `test_03_ea_aa_certs.sh` | EA/AA profiles, signatures, issuer digests |
| `test_04_tlm_ec_at.sh` | TLM, EC and AT profiles, key independence |
| `test_05_signing.sh` | CAM/DENM/external signing, negative cases, format conformance |
| `test_06_encryption.sh` | ECIES vectors, AES-CCM, (signed-and-)encrypted conformance, negative cases |
| `test_07_pki_init.sh` | full hierarchy, `save()`, EU-27 region |
| `test_08_coer_encoding.sh` | encodings, schema conformance, IEEE 1609.2 signing input, butterfly vectors and modes |
| `test_09_verification.sh` | signature, validity, revocation-by-hash, region, HashedId8 |

What each test demonstrates is mapped to requirements in [compliance](compliance.md).

`tests/test_vnap_secure_interface.py` is a contract test for vnap-secure's per-run PKI (§8.2):
the `src/` names and keyword arguments it uses, and butterfly key expansion consistency.

```bash
uv run --project tests/v3 python -m unittest tests/test_vnap_secure_interface.py
```

## 8. Using the output with Vanetza-NAP

The tool is validated against Vanetza-NAP [R24] with the vnap-secure harness [R30], which
depends on this repository in two ways.

### 8.1 Fixed certificate set (`gen-vnap-certs.sh`)

`gen-vnap-certs.sh` writes a Root CA, TLM, EA, AA, a regular AT and 24 butterfly ATs into
vnap-secure's `certs/c-its-pki/` (see §6). vnap-secure commits that set; its scenarios
with fixed certificate pools (`c-its-pki`, `c-its-pki-pseudo`, the tracking, mix-zone, convoy
and traffic scenarios) use it. Regenerate it before it expires or to produce a v2 set, then
run one of those scenarios in vnap-secure (`sim/`):

```bash
./vnapctl up c-its-pki && ./vnapctl check     # RSU (regular AT) and OBU (butterfly AT) exchange signed CAMs
./vnapctl down
```

### 8.2 Per-run PKI (`src/` package)

vnap-secure's `vnap-pki` image runs a fresh PKI for each simulation run: it provisions the
CA hierarchy, enrols the vehicles and issues butterfly ATs in batches while the run lasts.
The image is built from vnap-secure's `sim/images/pki/` plus this repository's `src/`
(copied to `/opt/cits-pki/src`). Its `pki_service.py` imports:

| Module | Names |
|---|---|
| `src.pki` | `CITSPKI`, `PKIEntity` |
| `src.certificates` | `issue_butterfly_authorization_tickets` |
| `src.crypto` | `bke_butterfly_private_key`, `bke_cocoon_private_key`, `bke_cocoon_public_key`, `deserialize_private_key`, `generate_keypair`, `public_key_to_point`, `random_bytes`, `serialize_private_key` |
| `src.types` | `Certificate`, `CertificateId`, `CertificateType`, `CertIdChoice`, `Duration`, `DurationChoice`, `EtsiVersion`, `IssuerChoice`, `IssuerIdentifier`, `PsidSsp`, `PublicKeyAlgorithm`, `ToBeSignedCertificate`, `ValidityPeriod`, `now_its_time32` |

These names, their signatures and the certificate encoding are an interface to vnap-secure.
The image installs `cryptography`, `tinyec` and `asn1tools` itself (not from
`pyproject.toml`), so a new runtime dependency of `src/` must be added to vnap-secure's
`sim/images/pki/Dockerfile` too.

- **Location:** vnap-secure includes this repository as a git submodule, `external/C-ITS-PKI`,
  pinned to a tested commit (`git clone --recurse-submodules`, or `git submodule update --init`).
  `CITS_PKI_DIR` overrides it, e.g. to try a working copy; a checkout next to vnap-secure is used
  when the submodule is not initialised.
- **Versions:** the image tag includes a digest of `src/`, so any change here builds a new
  image on the next run, and the image, the run's PKI container and the run's `run.json` record
  the C-ITS-PKI commit (`vnap.cits_pki`). vnap-secure moves its submodule to a newer commit only
  after a `[pki]` scenario and its check pass with it.
- **Contract test:** `tests/test_vnap_secure_interface.py` checks the names and keyword
  arguments above and that butterfly private and public key expansion agree; run it before
  pushing a change to `src/` (see §7).
- **Checking a change** in `src/` end to end: from vnap-secure's `sim/`, with `CITS_PKI_DIR`
  pointing at this working copy, run a scenario with its own PKI and its check:

```bash
./vnapctl up scenarios/templates/pki-refill.toml && ./vnapctl check   # expect pki.running==1, no starved stations
./vnapctl down
```

### 8.3 Offline message checks

```bash
# verify or parse one message file with Vanetza's own security stack
docker run --rm -v DIR:/w vnap:msgcheck v3 /w/cam.signed /w/at.cert /w/aa.cert /w/root_ca.cert
docker run --rm -v DIR:/w vnap:msgcheck decode-v3 /w/cam.enc
```

`vnap:msgcheck` is built with vnap-secure's `make msgcheck` (`sim/images/msgcheck/build-msgcheck.sh`). `DIR`
must be under the real `$HOME`, because snap-confined Docker cannot read `/mnt/hgfs` or
dot-directories.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Only --algo p256 is supported` | P-384 cannot be encoded in either format ([DD-02](design-decisions.md#dd-02)). |
| `ITS-AIDs [...] are not in the v2 AA certificate's ITS-AID list` | v2 ATs may only use AIDs the AA holds ([DD-06](design-decisions.md#dd-06)). |
| `message is signed with a certificate digest; the signer certificate is required` | pass `--at-cert` (or `signer_cert_encoded=`); digest-signed messages cannot be verified from a public key alone. |
| `not canonical COER` / `Invalid COER …` | the input is not a valid v3 structure (e.g. produced by a pre-2026-09 version of this tool); regenerate it. |
| `No matching certRecipInfo recipient` | the message was encrypted for another certificate. |
| Vanetza v2 reports `Unsigned_Message` for an external-payload message | Vanetza's v2 verifier only verifies payload type `signed`; the message itself is conformant ([compliance §4](compliance.md#4-etsi-ts-103-097-v121--v2-format)). |
| Vanetza (stock) rejects v2 certificates as `Missing_Subject_Assurance` | the certificates predate the KD-1 fix (2026-09-25); regenerate them. |
| `v2 generic signed messages need generation_location` / `not allowed for CAM/DENM` | TS 103 097 V1.2.1 clause 7.3 generic profile (non-CAM/DENM ITS-AIDs) requires a location; CAMs/DENMs cannot be encrypted or use external payloads in v2 ([DD-20](design-decisions.md#dd-20)). |
| `signed_external message: the external payload hash is required` | v2 external-payload messages carry no data; pass the same 32-byte hash used for signing as `external_payload_hash` ([DD-19](design-decisions.md#dd-19)). |
| Vanetza reports `Insufficient_ITS_AID` | the AT has no permission for the message's ITS-AID; issue it with `--psid` including that AID. |
