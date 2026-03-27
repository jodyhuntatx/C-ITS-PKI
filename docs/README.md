# C-ITS PKI Implementation

**ETSI TS 103 097 V2.2.1 — Cooperative Intelligent Transport Systems PKI**

A Python implementation of a complete C-ITS Public Key Infrastructure conforming to:

- **ETSI TS 103 097 V2.2.1** — ITS Security header and certificate formats (Release 2)
- **IEEE Std 1609.2™-2025** — Wireless Access in Vehicular Environments (WAVE) Security
- **ITU-T X.696** — Canonical Octet Encoding Rules (COER)

---
## Background Reading

 - [All You Need to Know About V2X PKI Certificates: Butterfly Key Expansion and Implicit Certificates](https://autocrypt.io/v2x-pki-certificates-butterfly-key-expansion-implicit-certificates/)

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
| COER encoding/decoding | ITU-T X.696 |
| EtsiTs103097Data-Signed (CAM/DENM) | ETSI TS 103 097 V2.2.1 §5.2 |
| EtsiTs103097Data-Encrypted | ETSI TS 103 097 V2.2.1 §5.3 |
| ECIES key encapsulation | IEEE 1609.2 §5.3.5 |
| AES-128-CCM symmetric encryption | IEEE 1609.2 §5.3.8 |
| Certificate chain verification | IEEE 1609.2 §5.1 |
| Hash ID-based revocation | ETSI TS 102 941 |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

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
├── ea.cert              # Enrolment Authority certificate
├── ea_sign.key          # EA signing key
├── ea_enc.key           # EA encryption key
├── aa.cert              # Authorization Authority certificate
├── aa_sign.key          # AA signing key
├── aa_enc.key           # AA encryption key
└── pki_meta.json        # PKI metadata
```

### 3. Enrol an ITS-Station

```bash
python cli.py enrol --output pki-output --name "ITS-Station-001"
```

### 4. Issue an Authorization Ticket

```bash
python cli.py issue-at --output pki-output --psid 36,37 --validity 168
```

### 5. Sign a CAM

```bash
echo -n "CAM_PAYLOAD" > cam.bin
python cli.py sign-cam \
    --at-key pki-output/tickets/at_*.key \
    --at-cert pki-output/tickets/at_*.cert \
    --payload cam.bin \
    --output cam.signed
```

### 6. Sign a DENM

```bash
echo -n "DENM_PAYLOAD" > denm.bin
python cli.py sign-denm \
    --at-key pki-output/tickets/at_*.key \
    --at-cert pki-output/tickets/at_*.cert \
    --payload denm.bin \
    --lat 52.5200 --lon 13.4050 \
    --output denm.signed

```

### 7. Encrypt a message (for the EA)

```bash
python cli.py encrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --payload cam.signed \
    --output cam.enc
```

### 8. Decrypt a message

```bash
python cli.py decrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --input cam.enc \
    --output cam.decrypted
```

### 9. Inspect a certificate

```bash
python cli.py info --cert pki-output/root_ca.cert
python cli.py verify-cert --cert pki-output/ea.cert --issuer pki-output/root_ca.cert
```

### 10. Verify a signature
Message signature only (fast, no chain):
```bash
python cli.py verify-sig \
  --signed  cam.signed \
  --at-cert pki-output/tickets/at_<ts>.cert
```
Full end-to-end verification (message + chain back to root):
```bash
python cli.py verify-sig \
  --signed  cam.signed \
  --at-cert pki-output/tickets/at_<ts>.cert \
  --aa      pki-output/aa.cert \
  --root    pki-output/root_ca.cert
```

---

## Python API

### Initialise the PKI

```python
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm

# Create and initialise PKI (P-256, EU-27 region)
pki = CITSPKI(
    algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
    region_ids=[65535]   # EU-27
)
certs = pki.initialise()

# Save to disk
pki.save("pki-output")
```

### Issue certificates

```python
# Enrol an ITS-Station → get Enrolment Credential
result = pki.enrol_its_station("ITS-Station-001")
ec_cert_bytes = result['ec']           # COER-encoded EC
ec_priv_key   = result['sign_priv_key']

# Issue an Authorization Ticket
at_result = pki.issue_authorization_ticket()
at_cert_bytes = at_result['at']        # COER-encoded AT
at_priv_key   = at_result['sign_priv_key']
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

# Sign a DENM (signer = full certificate, location required)
signed_denm = sign_denm(
    denm_payload=b"DENM binary data",
    at_priv_key=at_priv_key,
    at_cert_encoded=at_cert_bytes,
    generation_location=(525200000, 134050000, 340),  # Berlin
)

# Verify
result = verify_signed_data(signed_cam, at_public_key)
print(result['valid'])    # True
print(result['psid'])     # 36 (CAM ITS-AID)
```

### Encrypt and decrypt

```python
from src.encryption import encrypt_data, decrypt_data

# Encrypt for EA
encrypted = encrypt_data(
    plaintext=b"Confidential message",
    recipient_cert_encoded=ea_cert_bytes,
    recipient_enc_pub_key=ea_enc_pub_key,
)

# Decrypt at EA
plaintext = decrypt_data(
    encrypted_data_bytes=encrypted,
    recipient_enc_priv_key=ea_enc_priv_key,
    my_cert_encoded=ea_cert_bytes,
)
```

---

## Running Tests

```bash
cd /path/to/C-ITS-PKI
bash tests/run_all.sh
```

Individual test suites:

```bash
bash tests/test_01_keygen.sh
bash tests/test_02_root_ca.sh
bash tests/test_03_ea_aa_certs.sh
bash tests/test_04_tlm_ec_at.sh
bash tests/test_05_signing.sh
bash tests/test_06_encryption.sh
bash tests/test_07_pki_init.sh
bash tests/test_08_coer_encoding.sh
bash tests/test_09_verification.sh
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
| Root CA | 9.1 | self | name | ✗ | ✓ | CRL+CTL |
| TLM | 9.4 | self | name | ✗ | ✗ | CTL |
| EA | 9.2 | Root CA | name | ✓ | ✓ | CERT_REQUEST |
| AA | 9.3 | Root CA | name | ✓ | ✓ | CERT_REQUEST |
| EC | 9.5 | EA | name | ✗ | ✗ | CERT_REQUEST |
| AT | 9.6 | AA | **none** | ✗ | ✗ | CAM+DENM |

---

## Security Notes

- Private keys are stored as PEM (PKCS#8). In production, use an HSM (NFR-SEC-01).
- All random number generation uses Python's `os.urandom()` (system CSPRNG).
- AES-CCM nonces are freshly generated per encryption (NFR-SEC-04).
- AT certificate `id = none` ensures pseudonymity (NFR-SEC-06).
- AT and EC private keys are always independent key pairs (NFR-SEC-05).

---

## Project Structure

```
C-ITS-PKI/
├── src/
│   ├── __init__.py       Package init
│   ├── coer.py           COER (ITU-T X.696) encoding primitives
│   ├── types.py          ASN.1 data structure definitions
│   ├── encoding.py       Certificate COER encoder/decoder
│   ├── certificates.py   Certificate issuance (profiles 9.1–9.6)
│   ├── pki.py            PKI hierarchy manager
│   ├── signing.py        Message signing (EtsiTs103097Data-Signed)
│   ├── encryption.py     ECIES + AES-128-CCM encryption
│   └── verification.py   Certificate chain verification
├── tests/
│   ├── helpers.sh        Test helper functions
│   ├── run_all.sh        Test suite runner
│   ├── test_01_keygen.sh Key pair generation tests
│   ├── test_02_root_ca.sh Root CA profile tests
│   ├── test_03_ea_aa_certs.sh EA/AA certificate tests
│   ├── test_04_tlm_ec_at.sh TLM/EC/AT certificate tests
│   ├── test_05_signing.sh Message signing tests
│   ├── test_06_encryption.sh Encryption tests
│   ├── test_07_pki_init.sh Full PKI initialisation tests
│   ├── test_08_coer_encoding.sh COER encoding tests
│   └── test_09_verification.sh Certificate verification tests
├── docs/
│   ├── README.md         This file
│   └── architecture.md   System architecture documentation
├── cli.py                Command-line interface
└── requirements.txt      Python dependencies
```

---

### Opportunities for Enhancement

V2X (Vehicle-to-Everything) communication includes several message types beyond CAM (Cooperative Awareness Message) and DENM (Decentralized Environmental Notification Message).

**ETSI/European Standards**

- MAPEM (MAP Extended Message) — transmits intersection topology and lane geometry
- SPATEM (Signal Phase and Timing Extended Message) — conveys traffic light phase and timing info
- IVIM (Infrastructure to Vehicle Information Message) — delivers road signs and in-vehicle signage data
- SREM (Signal Request Extended Message) — allows vehicles (e.g., emergency or transit) to request signal priority
- SSEM (Signal Status Extended Message) — response from infrastructure to signal requests
- CPM (Collective Perception Message) — shares perceived objects (pedestrians, cyclists, other vehicles) detected by sensors
- VAM (Vulnerable Road User Awareness Message) — broadcast by VRUs like cyclists and pedestrians
- MCM (Maneuver Coordination Message) — used for negotiating cooperative maneuvers between vehicles
- IMZM (Interference Management Zone Message) — marks areas where radio interference may occur

**Other / Specialized**

- GeoNetworking messages — underlying transport layer messages specific to ETSI ITS
- SAM (Service Announcement Message) — advertises available V2X services in an area
- RTCM (Real-Time Correction Message) — delivers GNSS correction data for high-precision positioning

The landscape is still evolving, with CPM and MCM being relatively newer additions aimed at supporting higher levels of automation and cooperative driving.
---

## License

This implementation is provided for research and educational purposes.
Conformance to ETSI TS 103 097 V2.2.1 and IEEE Std 1609.2-2025 is the implementation goal.
