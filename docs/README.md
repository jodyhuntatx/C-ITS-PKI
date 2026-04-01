# C-ITS PKI Implementation

**ETSI TS 103 097 V2.2.1 — Cooperative Intelligent Transport Systems PKI**

A Python implementation of a complete C-ITS Public Key Infrastructure conforming to:

- **ETSI TS 103 097 V2.2.1** — ITS Security header and certificate formats (Release 2)
- **IEEE Std 1609.2™-2025** — Wireless Access in Vehicular Environments (WAVE) Security
- **IEEE 1609.2a** — Butterfly Key Expansion for Authorization Tickets
- **ITU-T X.696** — Canonical Octet Encoding Rules (COER)

---

## Background Reading

- [All You Need to Know About V2X PKI Certificates: Butterfly Key Expansion and Implicit Certificates](https://autocrypt.io/v2x-pki-certificates-butterfly-key-expansion-implicit-certificates/)
- [C-ITS-PKI Implementation notes](/docs/C-ITS-PKI\ Implementation\ Notes.md)

---

## Features

| Feature | Standard Reference |
|---|---|
| ECDSA P-256 / P-384 key generation | IEEE 1609.2 §5.3.1 |
| Root CA self-signed certificate | ETSI TS 103 097 V2.2.1 §7.2.1 |
| EA subordinate CA certificate | ETSI TS 103 097 V2.2.1 §7.2.2 |
| AA subordinate CA certificate | ETSI TS 103 097 V2.2.1 §7.2.3 |
| TLM self-signed certificate | ETSI TS 103 097 V2.2.1 §7.2.4 |
| Enrolment Credential (EC) issuance | ETSI TS 103 097 V2.2.1 §7.2.5 |
| Authorization Ticket (AT) issuance | ETSI TS 103 097 V2.2.1 §7.2.6 |
| Butterfly Key Expansion (BKE) batch AT issuance | IEEE 1609.2a §6.4.3.7 / ETSI TS 102 941 §6.2.3.3.1 |
| COER encoding/decoding | ITU-T X.696 |
| EtsiTs103097Data-Signed (CAM/DENM) | ETSI TS 103 097 V2.2.1 §5.2 |
| EtsiTs103097Data-Encrypted | ETSI TS 103 097 V2.2.1 §5.3 |
| ECIES key encapsulation | IEEE 1609.2 §5.3.5 |
| AES-128-CCM symmetric encryption | IEEE 1609.2 §5.3.8 |
| Certificate chain verification | IEEE 1609.2 §5.1 |
| AT profile validation (id=none, no certIssuePermissions) | ETSI TS 103 097 V2.2.1 §7.2.6 |
| Hash ID-based revocation check | ETSI TS 102 941 |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

Dependencies: `cryptography`, `tinyec>=0.4.0`

### 2. Initialise the PKI hierarchy

```bash
python cli.py init --output pki-output --algo p256 --region 65535
```

This creates:
```
pki-output/
├── root_ca.cert         # Root CA (self-signed, COER)
├── root_ca_sign.key     # Root CA signing key (PEM)
├── tlm.cert             # Trust List Manager certificate
├── tlm_sign.key         # TLM signing key
├── ea.cert              # Enrolment Authority certificate
├── ea_sign.key          # EA signing key
├── ea_enc.key           # EA encryption key
├── aa.cert              # Authorization Authority certificate
├── aa_sign.key          # AA signing key
├── aa_enc.key           # AA encryption key
└── pki_meta.json        # PKI metadata (algorithm, region, entity list)
```

### 3. Enrol an ITS-Station

```bash
python cli.py enrol --output pki-output --name "ITS-Station-001"
```

Output in `pki-output/its-stations/ITS-Station-001/`:
- `ec.cert` — Enrolment Credential (COER)
- `ec_sign.key` — EC signing private key (PEM)

### 4. Issue an Authorization Ticket

```bash
python cli.py issue-at --output pki-output --psid 36,37 --validity 168
```

Output in `pki-output/tickets/`:
- `at_<ts>.cert` — Authorization Ticket (COER, pseudonymous)
- `at_<ts>_sign.key` — AT signing private key (PEM)

### 5. Issue a BKE batch of Authorization Tickets

```bash
python cli.py butterfly-at --output pki-output --count 8 --validity 168
```

Output in `pki-output/bke-tickets/<ts>/`:
- `caterpillar_sign.key` — Caterpillar private key (keep secret, one per batch)
- `bke_at_N.cert` — AT certificate N (COER, pseudonymous)
- `bke_at_N_sign.key` — AT N signing private key (derived from caterpillar key)
- `bke_at_N.expansion` — Expansion value eᵢ used to derive AT N

The AA derives each AT public key as `Sᵢ = Cf + H(Cf‖eᵢ)·G` without ever
seeing the corresponding private key. The vehicle recovers each AT private key
locally as `sᵢ = (f + H(Cf‖eᵢ)) mod n`.

### 6. Sign a CAM

```bash
echo -n "CAM_PAYLOAD" > cam.bin
python cli.py sign-cam \
    --at-key pki-output/tickets/at_<ts>_sign.key \
    --at-cert pki-output/tickets/at_<ts>.cert \
    --payload cam.bin \
    --output cam.signed
```

BKE ATs are drop-in replacements — the signing interface is identical:

```bash
python cli.py sign-cam \
    --at-key pki-output/bke-tickets/<ts>/bke_at_0_sign.key \
    --at-cert pki-output/bke-tickets/<ts>/bke_at_0.cert \
    --payload cam.bin
```

### 7. Sign a DENM

```bash
echo -n "DENM_PAYLOAD" > denm.bin
python cli.py sign-denm \
    --at-key pki-output/tickets/at_<ts>_sign.key \
    --at-cert pki-output/tickets/at_<ts>.cert \
    --payload denm.bin \
    --lat 52.5200 --lon 13.4050 \
    --output denm.signed
```

### 8. Encrypt a message

```bash
python cli.py encrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --payload cam.signed \
    --output cam.enc
```

### 9. Decrypt a message

```bash
python cli.py decrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --input cam.enc \
    --output cam.decrypted
```

### 10. Inspect a certificate

```bash
python cli.py info --cert pki-output/root_ca.cert
python cli.py info --cert pki-output/bke-tickets/<ts>/bke_at_0.cert
```

### 11. Verify a certificate

```bash
# Verify any certificate (signature, validity, cracaId, permissions, region)
python cli.py verify-cert --cert pki-output/ea.cert --issuer pki-output/root_ca.cert

# Verify an AT or BKE AT — also runs AT profile checks (id=none, no certIssuePermissions)
python cli.py verify-cert \
    --cert pki-output/tickets/at_<ts>.cert \
    --issuer pki-output/aa.cert
```

### 12. Verify a signed message

Message signature only (fast, no chain):
```bash
python cli.py verify-sig \
    --signed cam.signed \
    --at-cert pki-output/tickets/at_<ts>.cert
```

Full end-to-end verification (message + certificate chain back to root):
```bash
python cli.py verify-sig \
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
from src.types import PublicKeyAlgorithm

pki = CITSPKI(
    algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
    region_ids=[65535]   # EU-27
)
certs = pki.initialise()
pki.save("pki-output")
```

### Issue certificates

```python
# Enrol an ITS-Station → Enrolment Credential
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
    generation_location=(525200000, 134050000, 340),  # Berlin (0.1 µdeg units)
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

Run `python cli.py <command> --help` for all options.

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

| Entity | Profile | Issuer | id | encKey | certIssuePerms | appPerms |
|---|---|---|---|---|---|---|
| Root CA | 9.1 | self | name | ✗ | ✓ | CRL + CTL |
| TLM | 9.4 | self | name | ✗ | ✗ | CTL |
| EA | 9.2 | Root CA | name | ✓ | ✓ | CERT_REQUEST |
| AA | 9.3 | Root CA | name | ✓ | ✓ | CERT_REQUEST |
| EC | 9.5 | EA | name | ✗ | ✗ | CERT_REQUEST |
| AT | 9.6 | AA | **none** | ✗ | ✗ | CAM + DENM |
| BKE AT | 9.6 | AA | **none** | ✗ | ✗ | CAM + DENM |

BKE ATs are structurally identical to standard ATs (same profile 9.6); they differ only in how the public key is derived.

---

## Project Structure

```
C-ITS-PKI/
├── src/
│   ├── __init__.py          Package init and public API exports
│   ├── coer.py              COER (ITU-T X.696) encoding primitives
│   ├── types.py             ASN.1 data structure definitions
│   ├── encoding.py          Certificate COER encoder/decoder
│   ├── crypto.py            ECDSA, ECIES, AES-128-CCM, BKE key expansion
│   ├── certificates.py      Certificate issuance (profiles 9.1–9.6, BKE batch)
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
│   └── architecture.md      System architecture documentation
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
- BKE caterpillar keys should be generated fresh per batch request and never reused across batches, to prevent the AA from linking batches.
- BKE expansion values `eᵢ` must be stored alongside AT certificates to allow re-derivation of AT private keys from the caterpillar key.

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
Conformance to ETSI TS 103 097 V2.2.1 and IEEE Std 1609.2-2025 is the implementation goal.
