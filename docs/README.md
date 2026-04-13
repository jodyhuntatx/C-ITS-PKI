# C-ITS PKI Implementation

**ETSI TS 103 097 — Cooperative Intelligent Transport Systems PKI**

A Python implementation of a complete C-ITS Public Key Infrastructure with support for two certificate encoding formats:

- **Vanetza-compatible binary format** (default) — ETSI TS 103 097 V1.2.1 (2015), as serialised by the [vanetza](https://github.com/riebl/vanetza) V2X simulator's `security/v2` layer
- **COER format** — ETSI TS 103 097 V2.2.1 (2021), IEEE Std 1609.2-2022/2025, ITU-T X.696

Both formats share the same PKI hierarchy, key material, and CLI interface. The encoding format is selected at `init` time via `--etsi-version` and is recorded in `pki_meta.json` so all subsequent commands use the correct decoder automatically.

Additional standards implemented:

- **IEEE 1609.2a** — Butterfly Key Expansion for Authorization Tickets
- **ETSI TS 102 941** — Trust and Privacy Management (BKE protocol reference)

---

## Background Reading

- [All You Need to Know About V2X PKI Certificates: Butterfly Key Expansion and Implicit Certificates](https://autocrypt.io/v2x-pki-certificates-butterfly-key-expansion-implicit-certificates/)
- [C-ITS-PKI Implementation notes](/docs/C-ITS-PKIImplementationNotes.md)
- [System Architecture](/docs/architecture.md)

---

## Features

| Feature | Standard Reference |
|---|---|
| ECDSA P-256 / P-384 key generation | IEEE 1609.2 §5.3.1 |
| Root CA self-signed certificate | ETSI TS 103 097 §7 |
| EA subordinate CA certificate | ETSI TS 103 097 §7 |
| AA subordinate CA certificate | ETSI TS 103 097 §7 |
| TLM self-signed certificate | ETSI TS 103 097 §7 |
| Enrolment Credential (EC) issuance | ETSI TS 103 097 §7 |
| Authorization Ticket (AT) issuance | ETSI TS 103 097 §7 |
| Butterfly Key Expansion (BKE) batch AT issuance | IEEE 1609.2a §6.4.3.7 / ETSI TS 102 941 §6.2.3.3.1 |
| **Vanetza-compatible binary encoding (V1.2.1)** | ETSI TS 103 097 V1.2.1, vanetza `security/v2` |
| COER encoding/decoding (V2.2.1) | ITU-T X.696 / IEEE 1609.2-2022 |
| EtsiTs103097Data-Signed (CAM/DENM) | ETSI TS 103 097 V2.2.1 §5.2 |
| EtsiTs103097Data-Encrypted | ETSI TS 103 097 V2.2.1 §5.3 |
| ECIES key encapsulation | IEEE 1609.2 §5.3.5 |
| AES-128-CCM symmetric encryption | IEEE 1609.2 §5.3.8 |
| Certificate chain verification | IEEE 1609.2 §5.1 |
| AT profile validation (id=none, no certIssuePermissions) | ETSI TS 103 097 §7 |
| Hash ID-based revocation check | ETSI TS 102 941 |

---

## Certificate Encoding Formats

### V1.2.1 — Vanetza-compatible binary (default)

The default format matches the wire encoding used by the vanetza simulator's `vanetza/security/v2/` C++ module (ETSI TS 103 097 V1.2.1, 2015-06, section 6.1). Certificates produced in this format can be loaded directly by vanetza's `certify` tool and any other V2X stack built on vanetza.

Key characteristics of the vanetza binary format:
- Certificate version byte = `0x02`
- Custom variable-length coding (not COER) for list sizes and ITS-AIDs (IntX)
- Subject-centric structure: `version · SignerInfo · SubjectInfo · SubjectAttributes · ValidityRestrictions · Signature`
- No IEEE 1609.2-2022 constructs (`cracaId`, `crlSeries`, `CertificateType`, presence bitmaps)
- `HashedId8` = last 8 bytes of SHA-256 of the full encoded certificate
- ECDSA P-256 only (vanetza v2 limitation)
- Duration encoded as a 2-byte word (bits 15–13 = units, bits 12–0 = value)

Typical encoded sizes (with EU-27 region):

| Certificate | Size |
|---|---|
| Root CA | 139 bytes |
| TLM | 127 bytes |
| EA | 176 bytes |
| AA | 176 bytes |
| Enrolment Credential | ~141 bytes |
| Authorization Ticket | ~126 bytes |
| BKE Authorization Ticket | ~126 bytes |

### V2.2.1 — COER format

The alternative format uses Canonical Octet Encoding Rules (ITU-T X.696) per IEEE Std 1609.2-2022/2025, ETSI TS 103 097 V2.2.1. Select with `--etsi-version v2`.

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

Dependencies: `cryptography`, `tinyec>=0.4.0`

### 2. Initialise the PKI hierarchy

```bash
# Default: vanetza-compatible V1.2.1 binary format
python3 cli.py init --output pki-output --algo p256 --region 65535

# Alternative: V2.2.1 COER format
python3 cli.py init --output pki-output --etsi-version v2
```

This creates:
```
pki-output/
├── root_ca.cert         # Root CA (self-signed)
├── root_ca_sign.key     # Root CA signing key (PEM)
├── tlm.cert             # Trust List Manager certificate
├── tlm_sign.key         # TLM signing key
├── ea.cert              # Enrolment Authority certificate
├── ea_sign.key          # EA signing key
├── ea_enc.key           # EA encryption key
├── aa.cert              # Authorization Authority certificate
├── aa_sign.key          # AA signing key
├── aa_enc.key           # AA encryption key
└── pki_meta.json        # PKI metadata (algorithm, region, etsi_version, entities)
```

### 3. Enrol an ITS-Station

```bash
python3 cli.py enrol --output pki-output --name "ITS-Station-001"
```

Output in `pki-output/its-stations/ITS-Station-001/`:
- `ec.cert` — Enrolment Credential
- `ec_sign.key` — EC signing private key (PEM)

### 4. Issue an Authorization Ticket

```bash
python3 cli.py issue-at --output pki-output --psid 36,37 --validity 168
```

Output in `pki-output/tickets/`:
- `at_<ts>.cert` — Authorization Ticket (pseudonymous)
- `at_<ts>_sign.key` — AT signing private key (PEM)

### 5. Issue a BKE batch of Authorization Tickets

```bash
python3 cli.py butterfly-at --output pki-output --count 8 --validity 168
```

Output in `pki-output/bke-tickets/`:
- `caterpillar_sign.key` — Caterpillar private key (keep secret, one per batch)
- `bke_at_N.cert` — AT certificate N (pseudonymous)
- `bke_at_N_sign.key` — AT N signing private key (derived from caterpillar key)
- `bke_at_N.expansion` — Expansion value eᵢ used to derive AT N

The AA derives each AT public key as `Sᵢ = Cf + H(Cf‖eᵢ)·G` without ever
seeing the corresponding private key. The vehicle recovers each AT private key
locally as `sᵢ = (f + H(Cf‖eᵢ)) mod n`.

### 6. Sign a CAM

```bash
echo -n "CAM_PAYLOAD" > cam.bin
python3 cli.py sign-cam \
    --at-key pki-output/tickets/at_<ts>_sign.key \
    --at-cert pki-output/tickets/at_<ts>.cert \
    --payload cam.bin \
    --output cam.signed
```

BKE ATs are drop-in replacements — the signing interface is identical:

```bash
python3 cli.py sign-cam \
    --at-key pki-output/bke-tickets/bke_at_0_sign.key \
    --at-cert pki-output/bke-tickets/bke_at_0.cert \
    --payload cam.bin
```

### 7. Sign a DENM

```bash
echo -n "DENM_PAYLOAD" > denm.bin
python3 cli.py sign-denm \
    --at-key pki-output/tickets/at_<ts>_sign.key \
    --at-cert pki-output/tickets/at_<ts>.cert \
    --payload denm.bin \
    --lat 52.5200 --lon 13.4050 \
    --output denm.signed
```

### 8. Encrypt a message

```bash
python3 cli.py encrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --payload cam.signed \
    --output cam.enc
```

### 9. Decrypt a message

```bash
python3 cli.py decrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --input cam.enc \
    --output cam.decrypted
```

### 10. Inspect a certificate

The `info` command auto-detects the encoding format from `pki_meta.json` in the certificate's directory:

```bash
python3 cli.py info --cert pki-output/root_ca.cert
python3 cli.py info --cert pki-output/bke-tickets/bke_at_0.cert
```

Example output for a vanetza-format Root CA:
```
============================================================
EtsiTs103097Certificate
============================================================
  Format          : ETSI TS 103 097 V1.2.1 (vanetza binary)
  Cert version    : 2  (vanetza v2 format)
  Subject type    : Root_CA (4)
  Issuer choice   : SELF
  Id choice       : NAME
  Name            : C-ITS-Root-CA
  ValidityPeriod  : start=2026-04-12T...Z  duration=10 YEARS
  Region IDs      : [65535]
  appPermissions  : ['CRL', 'CTL'] (PSIDs: [622, 617])
  encryptionKey   : absent
  verifyKey       : ECDSA_NIST_P256 03...
  Signature alg   : ECDSA_NIST_P256
  Encoded size    : 139 bytes
  HashedId8       : a82fad24d8d66bd4
```

Override auto-detection with `--etsi-version v1|v2` if needed.

### 11. Verify a certificate

```bash
# Verify any certificate (signature, validity, permissions, region)
python3 cli.py verify-cert --cert pki-output/ea.cert --issuer pki-output/root_ca.cert

# Verify an AT — also runs AT profile checks (id=none, no certIssuePermissions)
python3 cli.py verify-cert \
    --cert pki-output/tickets/at_<ts>.cert \
    --issuer pki-output/aa.cert
```

### 12. Verify a signed message

Message signature only (fast, no chain):
```bash
python3 cli.py verify-sig \
    --signed cam.signed \
    --at-cert pki-output/tickets/at_<ts>.cert
```

Full end-to-end verification (message + certificate chain back to root):
```bash
python3 cli.py verify-sig \
    --signed cam.signed \
    --at-cert pki-output/tickets/at_<ts>.cert \
    --aa pki-output/aa.cert \
    --root pki-output/root_ca.cert
```

---

## Python API

### Initialise the PKI

```python
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, EtsiVersion

# Default: vanetza-compatible V1.2.1 binary format
pki = CITSPKI(
    algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
    region_ids=[65535],           # EU-27
    version=EtsiVersion.V1_2_1,  # default
)
certs = pki.initialise()
pki.save("pki-output")

# Alternative: V2.2.1 COER format
pki_v2 = CITSPKI(
    algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
    region_ids=[65535],
    version=EtsiVersion.V2_2_1,
)
```

### Issue certificates

```python
# Enrol an ITS-Station -> Enrolment Credential
ec_result = pki.enrol_its_station("ITS-Station-001")
ec_cert_bytes = ec_result['ec']
ec_priv_key   = ec_result['sign_priv_key']

# Issue a standard Authorization Ticket
at_result = pki.issue_authorization_ticket()
at_cert_bytes = at_result['at']
at_priv_key   = at_result['sign_priv_key']

# Issue a BKE batch of Authorization Tickets
from src.crypto import generate_keypair, random_bytes
cat_priv, _ = generate_keypair(pki.algorithm)
expansion_values = [random_bytes(16) for _ in range(8)]

bke_tickets = pki.issue_butterfly_authorization_tickets(
    caterpillar_sign_priv=cat_priv,
    expansion_values=expansion_values,
    validity_hours=168,
)
# Each entry: {'at', 'certificate', 'sign_priv_key', 'sign_pub_key',
#              'expansion_value', 'priv_key_pem'}
```

### Decode a vanetza-format certificate

```python
from src.v1_encoding import decode_certificate_v1, hash_certificate_v1

cert_bytes = open("pki-output/root_ca.cert", "rb").read()
cert, _ = decode_certificate_v1(cert_bytes)

print(cert.tbs.id.name)                        # 'C-ITS-Root-CA'
print(cert.issuer.choice.name)                  # 'SELF'
print(cert.tbs.validity_period.duration.value)  # 10
print(hash_certificate_v1(cert_bytes).hex())    # HashedId8
```

### Sign messages

```python
from src.signing import sign_cam, sign_denm, verify_signed_data

# Sign a CAM (signer = digest by default)
signed_cam = sign_cam(
    cam_payload=b"CAM binary data",
    at_priv_key=at_priv_key,
    at_cert_encoded=at_cert_bytes,
)

# Sign a DENM (full certificate, location required)
signed_denm = sign_denm(
    denm_payload=b"DENM binary data",
    at_priv_key=at_priv_key,
    at_cert_encoded=at_cert_bytes,
    generation_location=(525200000, 134050000, 340),  # Berlin (0.1 udeg units)
)

# Verify
from src.crypto import load_public_key_from_compressed
result = verify_signed_data(signed_cam, at_public_key)
print(result['valid'])    # True
print(result['psid'])     # 36 (CAM ITS-AID)
```

### Encrypt and decrypt

```python
from src.encryption import encrypt_data, decrypt_data

encrypted = encrypt_data(
    plaintext=b"Confidential message",
    recipient_cert_encoded=ea_cert_bytes,
    recipient_enc_pub_key=ea_enc_pub_key,
)

plaintext = decrypt_data(
    encrypted_data_bytes=encrypted,
    recipient_enc_priv_key=ea_enc_priv_key,
    my_cert_encoded=ea_cert_bytes,
)
```

### Butterfly Key Expansion — low-level API

```python
from src.crypto import bke_expand_private_key, bke_expand_public_key
from src.certificates import issue_butterfly_authorization_tickets

# AA side: derive AT public keys and issue certificates
at_certs = issue_butterfly_authorization_tickets(
    caterpillar_sign_pub=caterpillar_pub,
    expansion_values=expansion_values,
    aa_cert=aa_cert,
    aa_priv_key=aa_priv_key,
    app_psids=psids,
    sign_algorithm=algorithm,
    validity_hours=168,
)

# Vehicle side: recover AT private key for certificate N
at_priv_n = bke_expand_private_key(caterpillar_priv, expansion_values[n])
```

---

## CLI Reference

| Command | Description |
|---|---|
| `init` | Initialise PKI hierarchy (Root CA, TLM, EA, AA) |
| `enrol` | Issue Enrolment Credential to an ITS-Station |
| `issue-at` | Issue a single Authorization Ticket |
| `butterfly-at` | Issue a BKE batch of Authorization Tickets |
| `sign-cam` | Sign a CAM payload with an AT |
| `sign-denm` | Sign a DENM payload with an AT and location |
| `verify-sig` | Verify a signed message (optionally with certificate chain) |
| `encrypt` | Encrypt a payload for a recipient (ECIES + AES-128-CCM) |
| `decrypt` | Decrypt an encrypted message |
| `verify-cert` | Verify a certificate's signature, validity, and profile constraints |
| `info` | Display detailed certificate information |

Run `python3 cli.py <command> --help` for all options.

The `--etsi-version` flag (`v1` or `v2`) is accepted by `init`, `verify-sig`, `encrypt`, `verify-cert`, and `info`. For all commands except `init` it is optional — the format is auto-detected from `pki_meta.json` in the certificate's directory tree, defaulting to `v1` if no metadata file is found.

---

## Running Tests

```bash
cd /path/to/C-ITS-PKI
bash tests/run_all.sh
```

Individual test suites:

```bash
bash tests/test_01_keygen.sh        # Key pair generation
bash tests/test_02_root_ca.sh       # Root CA profile
bash tests/test_03_ea_aa_certs.sh   # EA and AA certificates
bash tests/test_04_tlm_ec_at.sh     # TLM, EC, and AT certificates
bash tests/test_05_signing.sh       # CAM and DENM signing/verification
bash tests/test_06_encryption.sh    # ECIES + AES-128-CCM
bash tests/test_07_pki_init.sh      # Full PKI initialisation
bash tests/test_08_coer_encoding.sh # COER encoding/decoding
bash tests/test_09_verification.sh  # Certificate chain verification
```

---

## ITS-AID Values (ETSI TS 102 965)

| ITS-AID | Value | Description |
|---|---|---|
| CAM | 36 | Cooperative Awareness Message |
| DENM | 37 | Decentralized Environmental Notification Message |
| CTL | 617 | Certificate Trust List |
| CRL | 622 | Certificate Revocation List |
| CERT_REQUEST | 623 | Secure Certificate Request |
| MDM | 637 | Misbehaviour Detection Management |

---

## Certificate Profiles Summary

| Entity | V1.2.1 Profile | V2.2.1 Profile | Issuer | id | encKey | certIssuePerms | appPerms |
|---|---|---|---|---|---|---|---|
| Root CA | 7.1 | 9.1 | self | name | No | Yes | CRL + CTL |
| TLM | 7.4 | 9.4 | self | name | No | No | CTL |
| EA | 7.2 | 9.2 | Root CA | name | Yes | Yes | CERT_REQUEST |
| AA | 7.3 | 9.3 | Root CA | name | Yes | Yes | CERT_REQUEST |
| EC | 7.5 | 9.5 | EA | name | No | No | CERT_REQUEST |
| AT | 7.6 | 9.6 | AA | **none** | No | No | CAM + DENM |
| BKE AT | 7.6 | 9.6 | AA | **none** | No | No | CAM + DENM |

BKE ATs are structurally identical to standard ATs (same profile); they differ only in how the public key is derived.

---

## Project Structure

```
C-ITS-PKI/
├── src/
│   ├── __init__.py          Package init
│   ├── coer.py              COER (ITU-T X.696) encoding primitives
│   ├── types.py             Data structure definitions (EtsiVersion, Certificate, ...)
│   ├── encoding.py          COER certificate encoder/decoder (V2.2.1)
│   ├── v1_encoding.py       Vanetza binary encoder/decoder (V1.2.1)
│   ├── crypto.py            ECDSA, ECIES, AES-128-CCM, BKE key expansion
│   ├── certificates.py      Certificate issuance (all profiles, both formats, BKE batch)
│   ├── pki.py               PKI hierarchy manager (CITSPKI class)
│   ├── signing.py           Message signing (EtsiTs103097Data-Signed)
│   ├── encryption.py        ECIES + AES-128-CCM encryption/decryption
│   └── verification.py      Certificate chain and profile verification
├── tests/
│   ├── helpers.sh           Test helper functions and assertions
│   ├── run_all.sh           Full test suite runner
│   ├── test_01_keygen.sh    Key pair generation tests
│   ├── test_02_root_ca.sh   Root CA profile tests
│   ├── test_03_ea_aa_certs.sh  EA/AA certificate tests
│   ├── test_04_tlm_ec_at.sh TLM/EC/AT certificate tests
│   ├── test_05_signing.sh   Message signing tests
│   ├── test_06_encryption.sh   Encryption tests
│   ├── test_07_pki_init.sh  Full PKI initialisation tests
│   ├── test_08_coer_encoding.sh  COER encoding tests
│   └── test_09_verification.sh   Certificate verification tests
├── docs/
│   ├── README.md            This file
│   ├── architecture.md      System architecture documentation
│   └── C-ITS-PKIImplementationNotes.md  Implementation notes and FAQ
├── cli.py                   Command-line interface
├── gen-verify.sh            End-to-end functional test script
├── pyproject.toml           Python project metadata (uv)
└── requirements.txt         Python dependencies (cryptography, tinyec)
```

---

## Security Notes

- Private keys are stored as PEM (PKCS#8). In production, use an HSM (NFR-SEC-01).
- All random number generation uses Python's `os.urandom()` (system CSPRNG).
- AES-CCM nonces are freshly generated per encryption operation (NFR-SEC-04).
- AT certificate `id = none` ensures pseudonymity (NFR-SEC-06).
- AT and EC private keys are always independent key pairs (NFR-SEC-05).
- BKE caterpillar keys should be generated fresh per batch and never reused across batches, to prevent the AA from linking batches.
- BKE expansion values `eᵢ` must be stored alongside AT certificates to allow re-derivation of AT private keys from the caterpillar key.
- The vanetza format (V1.2.1) supports ECDSA/ECIES P-256 only. Use V2.2.1 (`--etsi-version v2`) if P-384 is required.

---

## Opportunities for Enhancement

V2X communication includes many message types beyond CAM and DENM. The ETSI/European standards define MAPEM, SPATEM, IVIM, SREM, SSEM, CPM, VAM, MCM, and IMZM. The North American SAE standards define BSM, RSA, TIM, EVA, PSM, SRM, SSM, PVD, and PDM. Adding `ItsAid` enum entries and signing profiles for these message types is a natural extension.

Other potential enhancements include:

- EC request/response protocol (ETSI TS 102 941 §6.2.2) for online enrolment
- AT request/response protocol (ETSI TS 102 941 §6.2.3) with privacy-preserving re-encryption
- Certificate Revocation List (CRL) generation and verification
- Misbehaviour reporting (ETSI TS 102 941 §6.4)
- Implicit (ECQV) certificate support

---

## License

This implementation is provided for research and educational purposes.
